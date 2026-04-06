from __future__ import annotations

from queue import Empty, Full, Queue
import threading


class ThreadSafeQueue:
    def __init__(self, maxsize: int = 0) -> None:
        self._queue: Queue = Queue(maxsize=maxsize)
        self._shutdown = False
        self._lock = threading.Lock()

    def push(self, item) -> bool:
        with self._lock:
            if self._shutdown:
                return False
        try:
            self._queue.put_nowait(item)
            return True
        except Full:
            return False

    def pop_with_timeout(self, timeout: float):
        with self._lock:
            if self._shutdown and self._queue.empty():
                return None
        try:
            return self._queue.get(timeout=timeout)
        except Empty:
            return None

    def empty(self) -> bool:
        return self._queue.empty()

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True
