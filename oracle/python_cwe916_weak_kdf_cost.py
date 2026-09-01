"""python-cwe916 -- key-derivation cost parameter that is a LITERAL below the configured floor.

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the line contains a recognized KDF call whose cost
parameter is an INTEGER LITERAL strictly below this decider's floor:

    hashlib.pbkdf2_hmac(...)  iterations < 100000
    hashlib.scrypt(...)       n          < 16384      (2**14)
    bcrypt.gensalt(...)       rounds     < 12

The floors are this decider's DECLARED PARAMETERS (see README) -- they are not a claim of universal law.
If the parameter is absent or non-literal, the verdict is SAFE: the decider does not guess at values it
cannot see. stdlib `ast` only; no code is executed.
"""
import ast

CWE = "CWE-916"

# hivas-nev -> (pozicionalis index, kulcsszo, minimum)
_COST = {
    "pbkdf2_hmac": (3, "iterations", 100000),
    "scrypt": (None, "n", 16384),
    "gensalt": (0, "rounds", 12),
}


def _callee(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _int_literal(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    # 2 ** 12 alaku literal
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
        a, b = _int_literal(node.left), _int_literal(node.right)
        if a is not None and b is not None and 0 <= b < 64:
            return a ** b
    return None


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != line:
            continue
        name = _callee(node)
        if name not in _COST:
            continue
        pos, kw, floor = _COST[name]
        val = None
        for k in node.keywords:
            if k.arg == kw:
                val = k.value
        if val is None and pos is not None and len(node.args) > pos:
            val = node.args[pos]
        if val is None:
            continue
        n = _int_literal(val)
        if n is not None and n < floor:
            return "FLAG"
    return "SAFE"
