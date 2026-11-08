import shlex
from dataclasses import dataclass, field
from typing import Callable, Any

@dataclass
class ParsedCommand:
    name:str
    args:list[str] = field(default_factory=list)
    flags:dict[str,Any] = field(default_factory=dict)

@dataclass
class _Registered:
    func: Callable
    min_args: int = 0
    help: str = ""

class CommandError(Exception):
    """user-facing error (unknown cmd, bad args, ...)."""

class Cap:
    def __init__(self):
        self._commands: dict[str, _Registered] = {}

    def command(self, name: str, min_agrs: int = 0, helpStr: str = ""):
        def decorator(func: Callable):
            self._commands[name] = _Registered(func, min_agrs, helpStr)
            return func
        return decorator

    def parse(self, raw: str) -> ParsedCommand:
        try:
            tokens = shlex.split(raw,posix=False)
        except ValueError as e:
            raise CommandError(f"bad quoting: {e}")

        if not tokens:
            raise CommandError("empty command")

        name, rest = tokens[0], tokens[1:]
        args:list[str] = []
        flags: dict[str, Any] = {}

        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok.startswith("--"):
                if "=" in tok:
                    k, v = tok[2:].split("=", 1)
                    flags[k] = v
                else:
                    flags[tok[2:]] = True
            else:
                args.append(tok)
            i += 1

        return ParsedCommand(name, args, flags)

    def run(self, command: str):
        parsed = self.parse(command)
        reg = self._commands.get(parsed.name)
        if reg is None:
            raise CommandError(f"unknown command: {parsed.name}")
        if len(parsed.args) < reg.min_args:
            raise CommandError(f"'{parsed.name}' needs at least {reg.min_args} arg(s)")
        return reg.func(parsed.args, parsed.flags)

