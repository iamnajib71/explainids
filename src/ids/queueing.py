"""How long would an attack wait behind this traffic's alert queue?

The Attack Night measure (docs/RESEARCH.md) for any scored traffic: an analyst reviews alerts first in, first out,
one every `service` seconds from the start of the recording. An attack alert raised at time t is noticed when the
analyst has cleared everything raised before it.
"""
from __future__ import annotations

import numpy as np

SERVICE_SECONDS = 60.0
STARTS = 20


def completion_times(alert_times: np.ndarray, service: float) -> np.ndarray:
    """When the analyst finishes each alert (alerts sorted by time, reviewed first in, first out)."""
    done = np.empty(len(alert_times), dtype=float)
    free = 0.0
    for i, t in enumerate(alert_times):
        free = max(free, t) + service
        done[i] = free
    return done


def queue_estimate(alert_times, span: float, service: float = SERVICE_SECONDS, starts: int = STARTS) -> dict | None:
    """Median and worst wait before an attack alert is looked at, over evenly spaced attack start times.

    Returns None when the recording is too short to say anything (under a minute)."""
    if not np.isfinite(span) or span < 60:
        return None
    times = np.sort(np.asarray(alert_times, dtype=float))
    done = completion_times(times, service)
    waits = []
    for t in np.linspace(0, span, starts + 2)[1:-1]:
        ahead = int(np.searchsorted(times, t, side="right"))
        free = done[ahead - 1] if ahead else 0.0
        waits.append(max(free, t) - t)
    per_hour = len(times) / (span / 3600)
    return {"alerts_per_hour": float(per_hour), "service_seconds": float(service), "span_seconds": float(span),
            "median_seconds": float(np.median(waits)), "worst_seconds": float(np.max(waits)),
            "keeps_up": bool(per_hour <= 3600 / service)}
