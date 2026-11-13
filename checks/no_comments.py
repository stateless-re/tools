import ast
import io
import sys
import tokenize
from pathlib import Path


def comment_lines(source: str) -> list[int]:
    lines = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            lines.append(token.start[0])
    return lines


def docstring_lines(source: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            lines.append(first.lineno)
    return lines


def main(root: str = ".") -> int:
    problems = []
    for path in sorted(Path(root).rglob("*.py")):
        if any(part.startswith(".") for part in path.parts):
            continue
        source = path.read_text(encoding="utf-8")
        problems += [f"{path}:{n}: comment" for n in comment_lines(source)]
        problems += [f"{path}:{n}: docstring" for n in docstring_lines(source)]
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
