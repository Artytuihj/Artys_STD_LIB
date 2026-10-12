import asyncio
import inspect

class ArtysEventManager:
    _events: dict[str, list] = {}
    _getters: dict[str,list] = {}

    @classmethod
    def Subscribe(cls, eventName:str):
        def decorator(func):
            cls._events.setdefault(eventName, []).append(func)
            return func
        return decorator

    @classmethod
    def On(cls, eventName: str, func):
        cls._events.setdefault(eventName, []).append(func)

    @classmethod
    def EmitEvent(cls, eventName:str, *args, **kwargs):
        for func in cls._events.get(eventName, []):
            if inspect.iscoroutinefunction(func):
                asyncio.create_task(func(*args, **kwargs))
            else:
                func(*args, **kwargs)

    def RegisterGetter(self, name, variable):
        pass


