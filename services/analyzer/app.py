"""
TENET AI - Analyzer Service
ML-based threat detection engine for LLM prompts.
"""
from prometheus_client import make_asgi_app
from services.utils.metrics import PrometheusMiddleware, increment_detection
from services.security import SecurityManager
from services.utils.logging_config import setup_logging
import os
import json
import asyncio
import sys
from datetime import datetime, timezone
from typing import Annotated, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as redis
try:
    import joblib
except ImportError:
    joblib = None  # type: ignore[assignment]

# Configure logging
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logger = setup_logging(__name__)

# Environment configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8100))
MODEL_PATH = os.getenv("MODEL_PATH", "./models/trained")
PROMPT_INJECTION_THRESHOLD = float(
    os.getenv("PROMPT_INJECTION_THRESHOLD", 0.75))
SHUTDOWN_TIMEOUT = float(os.getenv("SHUTDOWN_TIMEOUT", 10.0))

# FastAPI app
app = FastAPI(
    title="TENET AI - Analyzer Service",
    description="ML-based threat detection for LLM applications",
    version="0.1.0"
)

# CORS middleware - configurable origins for security
CORS_ALLOWED_ORIGINS = os.getenv(
    "CORS_ALLOWED_ORIGINS", "https://localhost:3000,https://localhost:5173")
allowed_origins = [origin.strip()
                   for origin in CORS_ALLOWED_ORIGINS.split(",")]
app.add_middleware(PrometheusMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Global state
redis_client: Optional[redis.Redis] = None
ml_model = None
vectorizer = None
stop_event: Optional[asyncio.Event] = None
background_task = None
security = SecurityManager(
    service_name="analyzer",
    redis_call=lambda coro: coro,
    redis_client_getter=lambda: None,
)


# Models
class AnalysisRequest(BaseModel):
    """Request model for prompt analysis.

    Attributes:
        prompt: The LLM prompt to be analyzed for threats. Must be between
            1 and 10,000 characters.
        context: Optional additional context to accompany the prompt.
            Maximum 5,000 characters.
    """
    prompt: str = Field(..., description="The prompt to analyze",
                        min_length=1, max_length=10000)
    context: Optional[str] = Field(
        None, description="Additional context", max_length=5000)


class AnalysisResponse(BaseModel):
    """Response model containing the threat analysis result.

    Attributes:
        risk_score: Numeric score between 0.0 and 1.0 indicating threat severity,
            where 1.0 represents the highest risk.
        verdict: Classification outcome. One of ``"benign"``, ``"suspicious"``,
            or ``"malicious"``.
        threat_type: Category of the detected threat (e.g. ``"prompt_injection"``,
            ``"jailbreak"``, ``"data_extraction"``). ``None`` if no threat detected.
        confidence: Confidence level of the verdict, between 0.0 and 1.0.
        details: Dictionary with additional metadata about the analysis, such as
            the detection method used and any matched patterns.
    """
    risk_score: float
    verdict: str
    threat_type: Optional[str] = None
    confidence: float
    details: dict


class HealthResponse(BaseModel):
    """Response model for the health check endpoint.

    Attributes:
        status: Current service status. Either ``"healthy"`` or ``"degraded"``.
        service: Name of the service (always ``"analyzer"``).
        version: Current service version string.
        model_loaded: Whether the ML model is loaded and ready.
        redis_connected: Whether the Redis connection is active.
    """
    status: str
    service: str
    version: str
    model_loaded: bool
    redis_connected: bool


@app.on_event("startup")
async def startup():
    """Initialize service dependencies on application startup.

    Performs the following steps in order:
        1. Establishes a connection to Redis using ``REDIS_HOST`` and ``REDIS_PORT``
           environment variables. Sets ``redis_client`` to ``None`` on failure so
           the service continues in a degraded state.
        2. Loads the ML prompt-detector model and its vectorizer from ``MODEL_PATH``.
           Logs a warning (but does not raise) if the model files are missing.
        3. Creates the ``stop_event`` used for graceful shutdown signalling and
           starts the ``process_event_queue`` background task.

    Raises:
        Does not raise; all exceptions are caught and logged so FastAPI can
        complete startup even when dependencies are unavailable.
    """
    global redis_client, ml_model, vectorizer, background_task, stop_event

    # Connect to Redis
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True
        )
        await redis_client.ping()
        logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    except Exception:
        logger.exception("Failed to connect to Redis")
        redis_client = None

    # Load ML models
    try:
        model_dir = Path(MODEL_PATH)
        model_file = model_dir / "prompt_detector.joblib"
        vectorizer_file = model_dir / "vectorizer.joblib"

        if model_file.exists() and vectorizer_file.exists():
            ml_model = joblib.load(model_file)
            vectorizer = joblib.load(vectorizer_file)
            logger.info("ML models loaded successfully")
        else:
            logger.warning(f"ML models not found at {MODEL_PATH}")
    except Exception:
        logger.exception("Failed to load ML models")

    # Create stop event and start background processor
    stop_event = asyncio.Event()
    background_task = asyncio.create_task(process_event_queue())


@app.on_event("shutdown")
async def shutdown():
    """Gracefully shut down service dependencies on application exit.

    Performs the following steps in order:
        1. Sets the ``stop_event`` to signal the background queue processor to stop.
        2. Awaits the background task for up to ``SHUTDOWN_TIMEOUT`` seconds.
           Cancels and suppresses ``CancelledError`` if the timeout is exceeded.
        3. Closes the Redis connection, suppressing any errors that occur during
           teardown so the shutdown sequence always completes cleanly.
    """
    global redis_client, stop_event, background_task

    # Signal the background task to stop
    if stop_event:
        stop_event.set()
        logger.info("Stop event set, waiting for background task to finish")

    # Wait for background task to complete gracefully
    if background_task:
        try:
            await asyncio.wait_for(background_task, timeout=SHUTDOWN_TIMEOUT)
            logger.info("Background task completed")
        except asyncio.TimeoutError:
            logger.warning(
                "Background task did not complete in time, cancelling")
            background_task.cancel()
            try:
                await background_task
            except asyncio.CancelledError:  # NOSONAR - Don't re-raise in shutdown handler, cancellation is expected
                logger.info("Background task cancelled successfully")

    # Close Redis connection
    if redis_client:
        try:
            await redis_client.close()
            logger.info("Redis connection closed")
        except Exception:
            logger.debug("Redis close failed during shutdown", exc_info=True)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Return the current health status of the analyzer service.

    Pings Redis to determine connectivity and checks whether the ML model
    is loaded. The overall status is ``"healthy"`` only when both Redis is
    reachable and the ML model is loaded; otherwise it is ``"degraded"``.

    Returns:
        HealthResponse: A response object containing the service name, version,
            model load status, Redis connectivity status, and an overall status
            string of either ``"healthy"`` or ``"degraded"``.
    """
    redis_connected = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_connected = True
        except Exception:
            logger.exception("Redis health check failed")
            redis_connected = False

    return HealthResponse(
        status="healthy" if redis_connected and ml_model else "degraded",
        service="analyzer",
        version="0.1.0",
        model_loaded=ml_model is not None,
        redis_connected=redis_connected
    )


@app.post(
    "/v1/analyze",
    response_model=AnalysisResponse,
    responses={
        401: {"description": "Invalid API key"},
        403: {"description": "Insufficient permissions"},
        429: {"description": "Rate limit or quota exceeded"}
    }
)
async def analyze_prompt(
    request: AnalysisRequest,
    x_api_key: Annotated[str, Header(...)]
):
    """Analyze a prompt for security threats.

    Authenticates the caller, runs heuristic and ML-based analysis on the
    supplied prompt via ``run_analysis``, increments Prometheus detection
    counters, and records an audit log entry.

    Args:
        request: The analysis request containing the prompt and optional context.
        x_api_key: API key passed in the ``X-Api-Key`` request header. Must have
            the ``"analyze"`` permission.

    Returns:
        AnalysisResponse: The analysis result including risk score, verdict,
            threat type, confidence, and method details.

    Raises:
        HTTPException 401: If the provided API key is invalid.
        HTTPException 403: If the API key lacks the ``"analyze"`` permission.
        HTTPException 429: If the caller has exceeded their rate limit or quota.
    """
    auth = await security.require_auth(x_api_key, required_permission="analyze")
    prompt = request.prompt
    result = run_analysis(prompt)

    increment_detection(service="analyzer",
                        threat_type=result.threat_type, verdict=result.verdict)

    security.audit(
        action="analyze_prompt",
        result=result.verdict,
        context=auth,
        metadata={"risk_score": result.risk_score,
                  "threat_type": result.threat_type},
    )
    return result


def run_analysis(prompt: str) -> AnalysisResponse:
    """Combine heuristic and ML analysis to produce a final threat verdict.

    Runs heuristic rule matching first and, if the ML model is available,
    also runs ML-based classification. The two results are merged using the
    following priority order:

    1. **Malicious (heuristic)** – heuristic risk score > 0.8 → verdict
       ``"malicious"``, confidence 0.95.
    2. **Malicious (ML)** – ML risk score above ``PROMPT_INJECTION_THRESHOLD``
       → verdict and confidence taken from the ML result.
    3. **Suspicious (heuristic)** – heuristic risk score between 0.5 and 0.8
       → verdict ``"suspicious"``, confidence 0.6, recommendation ``"manual_review"``.
    4. **Suspicious (ML)** – ML risk score between 0.5 and threshold → verdict
       ``"suspicious"`` with ML confidence, recommendation ``"manual_review"``.
    5. **Benign** – all scores below 0.5 → verdict ``"benign"``, confidence 0.85.

    Args:
        prompt: The raw prompt string to evaluate.

    Returns:
        AnalysisResponse: The combined analysis result with risk score, verdict,
            threat type, confidence level, and detection method details.
    """
    # Heuristic analysis
    heuristic_result = heuristic_analysis(prompt)

    # ML analysis (if model is loaded)
    ml_result = ml_analysis(prompt) if ml_model else None

    # Combine results
    if heuristic_result["risk_score"] > 0.8:
        return AnalysisResponse(
            risk_score=heuristic_result["risk_score"],
            verdict=heuristic_result["verdict"],
            threat_type=heuristic_result["threat_type"],
            confidence=0.95,
            details={
                "method": "heuristic",
                "matched_patterns": heuristic_result.get("patterns", [])
            }
        )
    elif ml_result and ml_result["risk_score"] > PROMPT_INJECTION_THRESHOLD:
        return AnalysisResponse(
            risk_score=ml_result["risk_score"],
            verdict=ml_result["verdict"],
            threat_type=ml_result["threat_type"],
            confidence=ml_result["confidence"],
            details={"method": "ml", "model_version": "0.1"}
        )
    elif heuristic_result["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=heuristic_result["risk_score"],
            verdict="suspicious",
            threat_type=heuristic_result["threat_type"],
            confidence=0.6,
            details={"method": "heuristic", "recommendation": "manual_review"}
        )
    elif ml_result and ml_result["risk_score"] > 0.5:
        return AnalysisResponse(
            risk_score=ml_result["risk_score"],
            verdict="suspicious",
            threat_type=ml_result["threat_type"],
            confidence=ml_result["confidence"],
            details={"method": "ml", "model_version": "0.1",
                     "recommendation": "manual_review"}
        )
    else:
        return AnalysisResponse(
            risk_score=max(
                heuristic_result["risk_score"], ml_result["risk_score"] if ml_result else 0.0),
            verdict="benign",
            threat_type=None,
            confidence=0.85,
            details={"method": "combined"}
        )


def heuristic_analysis(prompt: str) -> dict:
    """Perform rule-based heuristic threat detection on a prompt.

    Scans the lowercased prompt against a curated set of known malicious
    patterns grouped into three threat categories:

    - ``"prompt_injection"``: Attempts to override or ignore system instructions.
    - ``"jailbreak"``: Attempts to remove safety constraints from the model.
    - ``"data_extraction"``: Attempts to extract internal system prompts or rules.

    Each pattern carries a pre-assigned risk score. The highest-scoring matched
    pattern determines the final risk score and threat type.

    Args:
        prompt: The raw prompt string to evaluate.

    Returns:
        dict: A dictionary with the following keys:

            - ``risk_score`` (float): Highest matched pattern score (0.0–1.0).
            - ``verdict`` (str): ``"malicious"`` if score > 0.8, ``"suspicious"``
              if score > 0.5, otherwise ``"benign"``.
            - ``threat_type`` (str | None): Category of the highest-scoring
              matched pattern, or ``None`` if no patterns matched.
            - ``patterns`` (list[str]): All matched pattern strings.
    """
    prompt_lower = prompt.lower()
    matched_patterns = []
    max_score = 0.0
    threat_type = None

    # Pattern definitions with scores
    patterns = {
        "prompt_injection": {
            "ignore previous instructions": 0.95,
            "ignore all previous": 0.95,
            "disregard your instructions": 0.90,
            "forget your system prompt": 0.90,
            "override system": 0.85,
            "</s>": 0.90,
            "<|system|>": 0.95,
            "\n\n###": 0.80,
        },
        "jailbreak": {
            "do anything now": 0.90,
            "you are now dan": 0.95,
            "no restrictions": 0.80,
            "bypass your programming": 0.85,
            "override your safety": 0.90,
            "evil mode": 0.85,
            "developer mode": 0.80,
        },
        "data_extraction": {
            "show me your system prompt": 0.75,
            "what are your instructions": 0.70,
            "reveal your training": 0.75,
            "list your rules": 0.65,
        }
    }

    for category, category_patterns in patterns.items():
        for pattern, score in category_patterns.items():
            if pattern in prompt_lower:
                matched_patterns.append(pattern)
                if score > max_score:
                    max_score = score
                    threat_type = category

    verdict = "benign"
    if max_score > 0.8:
        verdict = "malicious"
    elif max_score > 0.5:
        verdict = "suspicious"

    return {
        "risk_score": max_score,
        "verdict": verdict,
        "threat_type": threat_type,
        "patterns": matched_patterns
    }


def ml_analysis(prompt: str) -> dict:
    """Perform ML-based threat classification on a prompt.

    Vectorizes the prompt using the globally loaded TF-IDF (or equivalent)
    vectorizer, then passes the resulting feature vector through the trained
    binary classifier to obtain malicious probability scores.

    Verdict thresholds:
        - ``"malicious"`` if malicious probability > ``PROMPT_INJECTION_THRESHOLD``.
        - ``"suspicious"`` if probability is between 0.5 and the threshold.
        - ``"benign"`` otherwise.

    Args:
        prompt: The raw prompt string to classify.

    Returns:
        dict: A dictionary with the following keys:

            - ``risk_score`` (float): Probability that the prompt is malicious (0.0–1.0).
            - ``verdict`` (str): One of ``"malicious"``, ``"suspicious"``,
              ``"benign"``, ``"unknown"`` (model not loaded), or ``"error"``
              (exception during inference).
            - ``threat_type`` (str | None): ``"prompt_injection"`` if risk score
              > 0.5, otherwise ``None``.
            - ``confidence`` (float): Highest probability across all classes,
              indicating model certainty.
    """
    global ml_model, vectorizer

    if not ml_model or not vectorizer:
        return {"risk_score": 0.0, "verdict": "unknown", "threat_type": None, "confidence": 0.0}

    try:
        # Vectorize the prompt
        X = vectorizer.transform([prompt])

        # Get prediction probabilities
        proba = ml_model.predict_proba(X)[0]

        # Assuming binary classification: [benign, malicious]
        malicious_prob = proba[1] if len(proba) > 1 else proba[0]

        verdict = "malicious" if malicious_prob > PROMPT_INJECTION_THRESHOLD else "benign"
        if 0.5 < malicious_prob <= PROMPT_INJECTION_THRESHOLD:
            verdict = "suspicious"

        return {
            "risk_score": float(malicious_prob),
            "verdict": verdict,
            "threat_type": "prompt_injection" if malicious_prob > 0.5 else None,
            "confidence": float(max(proba))
        }
    except Exception:
        logger.exception("ML analysis error")
        return {"risk_score": 0.0, "verdict": "error", "threat_type": None, "confidence": 0.0}


async def _wait_for_stop_event():
    """Wait until the global ``stop_event`` is set.

    Acts as a thin wrapper around ``stop_event.wait()`` with a defensive
    guard for the case where ``stop_event`` has not yet been initialised
    (e.g. if called before ``startup`` completes).

    Returns immediately without blocking if ``stop_event`` is ``None``.
    """
    # Defensive check: ensure stop_event exists before awaiting
    if stop_event is None:
        return
    await stop_event.wait()


async def _wait_with_timeout(seconds: float):
    """Wait for the stop event with a maximum timeout, ignoring ``TimeoutError``.

    Wraps ``_wait_for_stop_event`` inside an ``asyncio.timeout`` context so
    callers can use it as a cancellable sleep that also exits early when the
    service is shutting down.

    Args:
        seconds: Maximum number of seconds to wait before returning, regardless
            of whether the stop event has been set.
    """
    try:
        async with asyncio.timeout(seconds):
            await _wait_for_stop_event()
    except asyncio.TimeoutError:
        pass


async def _update_and_store_event(event: dict, event_id: str, result: AnalysisResponse):
    """Persist analysis results for an event back to Redis.

    Enriches the ``event`` dictionary in-place with the analysis outcome,
    serialises it to JSON, and stores it under the key
    ``tenet:event:<event_id>`` with a 24-hour TTL.

    If the verdict is ``"malicious"``, the enriched event is also prepended
    to the ``tenet:alerts`` Redis list for downstream alert processing.

    Args:
        event: The original event dictionary retrieved from the queue.
            Modified in-place with analysis fields before storage.
        event_id: Unique identifier for the event, used as part of the Redis key.
        result: The ``AnalysisResponse`` produced by ``run_analysis``.

    Note:
        If ``redis_client`` is ``None`` (e.g. Redis is unavailable), the
        function logs a warning and returns without storing anything.
    """
    # Ensure redis_client is available
    if not redis_client:
        logger.warning(
            f"Cannot store event {event_id}: Redis client not available")
        return

    # Update the event with analysis results
    event["analyzed"] = True
    event["risk_score"] = result.risk_score
    event["verdict"] = result.verdict
    event["threat_type"] = result.threat_type
    event["analysis_details"] = result.details
    event["analyzed_at"] = datetime.now(timezone.utc).isoformat()

    # Store updated event
    await redis_client.set(
        f"tenet:event:{event_id}",
        json.dumps(event),
        ex=86400
    )

    # If malicious, add to alerts
    if result.verdict == "malicious":
        await redis_client.lpush("tenet:alerts", json.dumps(event))
        logger.warning(f"Alert: Malicious event detected - {event_id}")


async def _process_single_event(event_json: str):
    """Parse, validate, and analyze a single raw event from the queue.

    Performs the following steps:
        1. Deserializes the JSON string to a dictionary.
        2. Validates that ``event_id`` is present, a non-empty string, and
           no longer than 255 characters.
        3. Validates that the ``prompt`` field is a non-empty string and
           truncates it to 10,000 characters if it exceeds that limit.
        4. Calls ``run_analysis`` on the prompt and increments background
           Prometheus counters.
        5. Delegates persistence to ``_update_and_store_event``.

    Args:
        event_json: Raw JSON string representing a single event object
            dequeued from ``tenet:events:queue``.

    Note:
        Invalid events (malformed JSON, missing/invalid ``event_id``, empty
        or non-string prompt) are logged and silently skipped so that one
        bad event does not block the queue.
    """
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError:
        logger.exception("Failed to parse event JSON")
        return

    # Validate event structure
    if not isinstance(event, dict):
        logger.warning("Event is not a dictionary, skipping")
        return

    # Validate event_id presence and format
    event_id = event.get('event_id')
    if not event_id or not isinstance(event_id, str):
        # Log only safe metadata, avoid exposing sensitive prompts
        safe_summary = {
            "user_id": event.get('user_id'),
            "timestamp": event.get('timestamp'),
            "has_prompt": 'prompt' in event,
            "prompt_length": len(event.get('prompt', '')) if isinstance(event.get('prompt'), str) else 0
        }
        logger.warning(
            f"Skipping event without valid event_id. Safe metadata: {safe_summary}")
        return

    # Additional event_id validation
    event_id = event_id.strip()
    if not event_id:
        logger.warning("Skipping event with empty event_id after stripping")
        return

    if len(event_id) > 255:
        logger.warning(
            f"Skipping event with overly long event_id ({len(event_id)} chars)")
        return

    logger.info(f"Processing event: {event_id}")

    # Get and validate prompt
    prompt = event.get("prompt", "")
    if not isinstance(prompt, str):
        logger.warning(f"Event {event_id} has invalid prompt type, skipping")
        return

    if not prompt.strip():
        logger.warning(f"Event {event_id} has empty prompt, skipping")
        return

    # Truncate very long prompts for safety
    if len(prompt) > 10000:
        logger.warning(
            f"Event {event_id} has overly long prompt ({len(prompt)} chars), truncating")
        prompt = prompt[:10000]

    # Analyze the prompt
    result = run_analysis(prompt)

    increment_detection(service="analyzer_bg",
                        threat_type=result.threat_type, verdict=result.verdict)

    # Update and store event
    await _update_and_store_event(event, event_id, result)


async def process_event_queue():
    """Background task that continuously processes events from the Redis queue.

    Runs in a loop until the ``stop_event`` is set (triggered during
    application shutdown). On each iteration:

    - If Redis is unavailable, waits 5 seconds before retrying.
    - Pops the rightmost element from ``tenet:events:queue`` (RPOP).
    - If an event is found, delegates processing to ``_process_single_event``.
    - If the queue is empty, waits 1 second before polling again.
    - On unexpected exceptions, logs the error and waits 5 seconds to
      avoid tight error loops.

    This function is started as an ``asyncio`` task during ``startup`` and
    is awaited (with a timeout) during ``shutdown``.
    """
    global stop_event, redis_client

    while not stop_event.is_set():
        try:
            if not redis_client:
                await _wait_with_timeout(5.0)
                continue

            # Pop event from queue
            event_json = await redis_client.rpop("tenet:events:queue")

            if event_json:
                await _process_single_event(event_json)
            else:
                await _wait_with_timeout(1.0)

        except Exception:
            logger.exception("Queue processing error")
            await _wait_with_timeout(5.0)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
