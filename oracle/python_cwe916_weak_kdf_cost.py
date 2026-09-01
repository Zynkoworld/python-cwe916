"""python-cwe916 -- key-derivation cost parameter that is a LITERAL below the declared floor.

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the line contains a call that resolves, through the
module's import bindings, to a recognized KDF whose cost parameter is an integer literal strictly
below this decider's floor:

    hashlib.pbkdf2_hmac(...)  iterations < 100000
    hashlib.scrypt(...)       n          < 16384      (2**14)
    bcrypt.gensalt(...)       rounds     < 12

The floors are this decider's DECLARED PARAMETERS (see README) -- not a claim of universal law. If the
parameter is absent or non-literal, the verdict is SAFE: the decider does not guess at values it
cannot see. A module's own `def gensalt(...)` shadows the library name and is NOT flagged.
stdlib `ast` only; no code is executed.
"""
import ast

CWE = "CWE-916"
_COST = {"hashlib.pbkdf2_hmac": (3, "iterations", 100000),
         "hashlib.scrypt": (None, "n", 16384),
         "bcrypt.gensalt": (0, "rounds", 12)}
# --- import-kotes feloldas (zafire #19219: a dontes a KOTESRE alljon, ne a nevre) ---

def _dotted(node):
    """a.b.c -> "a.b.c"; barmi mas -> None"""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _resolve(dotted, binds):
    head, _, rest = dotted.partition(".")
    if head in binds:
        return binds[head] + ("." + rest if rest else "")
    return dotted


def _bindings(tree):
    """lokalis nev -> teljes (pontozott) eredet: importok + egyszeru referencia-atadas."""
    binds = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                binds[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            for a in n.names:
                binds[a.asname or a.name] = (mod + "." + a.name) if mod else a.name
    for n in ast.walk(tree):          # f = hashlib.md5  ->  f kotese hashlib.md5
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            d = _dotted(n.value)
            if d:
                binds[n.targets[0].id] = _resolve(d, binds)
    return binds


def _local_defs(tree):
    """a modul altal MAGA definialt nevek -- ezek arnyekoljak az azonos nevu konyvtari hivast."""
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
    return out


def _origin(call, binds, local, consts=None):
    """A hivott dolog KOTES szerinti teljes neve. None = nem eldontheto. '<local>.' = sajat definicio.

    A getattr-ag feloldja a konstans attributum-nevet is -- literalkent (`getattr(m, "md5")`) ES
    konstanshoz kotott nevkent (`n = "md5"; getattr(m, n)`). A VALODIAN dinamikus nev (`n = pick()`)
    nem oldhato fel a forrasbol; ott None a valasz, nem tipp.
    """
    f = call.func
    if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr" \
            and "getattr" not in local and len(f.args) >= 2:
        attr = f.args[1]
        name = None
        if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
            name = attr.value
        elif isinstance(attr, ast.Name) and consts and attr.id in consts:
            c = consts[attr.id]
            name = c.decode("utf-8", "replace") if isinstance(c, bytes) else c
        if not isinstance(name, str):
            return None
        base = _dotted(f.args[0])
        return _resolve(base + "." + name, binds) if base else None
    d = _dotted(f)
    if d is None:
        return None
    head = d.split(".")[0]
    if head in local and head not in binds:
        return "<local>." + d
    return _resolve(d, binds)


def _fold_str(node, tbl):
    """Statikusan kihajthato string/bytes ertek, vagy None.

    Kihajtja a konstans-osszefuzest (`'md' + '5'`) es a csak-konstans f-stringet (`f'md{5}'`), es
    feloldja a mar ismert neveket -- de csak azokat, amelyek EDDIG kerultek a tablaba, igy a
    sorrend-tudatos (last-write-wins) viselkedes megmarad.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value
    if isinstance(node, ast.Name):
        return tbl.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _fold_str(node.left, tbl), _fold_str(node.right, tbl)
        if isinstance(a, str) and isinstance(b, str):
            return a + b
        if isinstance(a, bytes) and isinstance(b, bytes):
            return a + b
        return None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue) and v.format_spec is None \
                    and v.conversion in (-1, None):
                inner = v.value
                if isinstance(inner, ast.Constant) and isinstance(inner.value, (str, int, float)) \
                        and not isinstance(inner.value, bool):
                    parts.append(str(inner.value))
                else:
                    c = _fold_str(inner, tbl)
                    if not isinstance(c, str):
                        return None
                    parts.append(c)
            else:
                return None
        return "".join(parts)
    return None


def _const_strs(tree):
    """Egyszeru `NEV = <statikusan kihajthato string/bytes>` ertekadasok BARHOL a fajlban.

    Kihajtja a konstans-osszefuzest es a csak-konstans f-stringet is -- egy nev akkor szamit
    ismertnek, ha az ERTEKE a forrasbol kiszamolhato, nem csak ha puszta literal.

    FONTOS es szandekosan kimondva: ez NEM scope-erzekeny -- egy fuggvenyen BELULI ertekadas is
    bekerul, es igy egy masik fuggvenyben szereplo AZONOS NEVU valtozora is ervenyesnek latszik.
    Ez tudatos TUL-KOZELITES a rejtett literal fele; az arat a known_limitations.jsonl rogziti.
    A tabla SORREND-TUDATOS: a kesobbi ertekadas felulirja a korabbit (last-write-wins).
    """
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            v = _fold_str(n.value, out)
            if v is None:
                continue
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = v
    return out


def _int_literal(node, consts=None):
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name) and consts and node.id in consts:   # ITER = 1000; pbkdf2(..., ITER)
        return consts[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
        a, b = _int_literal(node.left, consts), _int_literal(node.right, consts)
        if a is not None and b is not None and 0 <= b < 64:
            return a ** b
    return None


def _const_ints(tree):
    """Egyszeru `NEV = <egesz>` ertekadasok BARHOL a fajlban -- NEM scope-erzekeny
    (ld. known_limitations.jsonl).
    """
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, int) and not isinstance(n.value.value, bool):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = n.value.value
    return out


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    binds, local, consts = _bindings(tree), _local_defs(tree), _const_ints(tree)
    sconsts = _const_strs(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != line:
            continue
        origin = _origin(node, binds, local, sconsts)
        if not origin or origin not in _COST:
            continue
        pos, kw, floor = _COST[origin]
        val = None
        for k in node.keywords:
            if k.arg == kw:
                val = k.value
        if val is None and pos is not None and len(node.args) > pos:
            val = node.args[pos]
        if val is None:
            continue
        n = _int_literal(val, consts)
        if n is not None and n < floor:
            return "FLAG"
    return "SAFE"
