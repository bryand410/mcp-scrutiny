"""Ablation : le detecteur est-il structurel, ou appareilleur de vocabulaire ?

Question posee par l'issue #5 et par le commentaire de cc-bb-aa : les motifs par
langue seront-ils toujours en retard, ou le modele tient-il deja par la structure ?

Methode : on met a zero les features derivees de listes de mots ANGLAIS, on
reentraine, et on compare le rappel par langue au modele complet. Meme
construction de plis que `model.cross_validate` (graine 0), pour que les chiffres
soient comparables.

    python scripts/ablation_language.py
"""

from __future__ import annotations

import random
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mcp_scrutiny.model as M
from mcp_scrutiny.corpus import BENIGN, MALICIOUS
from mcp_scrutiny.features import FEATURE_NAMES

# --------------------------------------------------------------------------- #
# Les features derivees de listes de mots anglaises.
# Les 5 dernieres sont des PRODUITS des comptages : elles tombent avec eux.
# --------------------------------------------------------------------------- #
ENGLISH_DERIVED = frozenset(
    {
        "injection_markers",
        "concealment",
        "urgency",
        "directive",
        "hidden_recipient",
        "redaction_language",
        "cross_tool",
        "imperative_density",
        "conceal_x_exfil",
        "cred_x_exfil",
        "fs_x_exfil",
        "cross_x_urgency",
        "recipient_x_exfil",
    }
)
assert set(FEATURE_NAMES) >= ENGLISH_DERIVED, "nom de feature inconnu"

# --------------------------------------------------------------------------- #
# Etiquetage de langue. Le corpus ne porte aucune metadonnee, donc on tague par
# heuristique et on IMPRIME le resultat pour verification humaine.
# --------------------------------------------------------------------------- #
_ACCENT = re.compile(r"[àâäéèêëîïôöùûüÿçœæÀÂÄÉÈÊËÎÏÔÖÙÛÜŸÇŒÆ]")
_FR_WORDS = re.compile(
    r"\b(le|la|les|des|une|un|du|pour|avec|sans|vous|votre|vos|ne|pas|jamais|"
    r"toujours|avant|après|numéro|fichier|doit|doivent|cette|est|sont|dans|aux)\b",
    re.I,
)


def langue(text: str) -> str:
    return "fr" if (_ACCENT.search(text) or len(_FR_WORDS.findall(text)) >= 3) else "en"


def _wrap(item):
    return M._FakeTool(item) if isinstance(item, str) else item


def _texte(item) -> str:
    return item if isinstance(item, str) else str(getattr(item, "description", ""))


# --------------------------------------------------------------------------- #
# Validation croisee, en gardant la langue de chaque echantillon de test.
# --------------------------------------------------------------------------- #
def cv_par_langue(echantillons, *, k=5, epochs=2000, lr=0.5, l2=1e-3):
    pos = [s for s in echantillons if s[1] == 1]
    neg = [s for s in echantillons if s[1] == 0]
    rng = random.Random(0)
    rng.shuffle(pos)
    rng.shuffle(neg)

    plis: list[list] = [[] for _ in range(k)]
    for i, it in enumerate(pos):
        plis[i % k].append(it)
    for i, it in enumerate(neg):
        plis[i % k].append(it)

    # langue -> [touche, manque, fausse_alarme, rejete_a_tort]
    stats: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    tous = [0, 0, 0, 0]

    for i in range(k):
        entrainement = [s for j, pli in enumerate(plis) if j != i for s in pli]
        modele = M.train(entrainement, epochs=epochs, lr=lr, l2=l2)
        for item, y in plis[i]:
            feats = M.extract_features(_wrap(item))
            p = modele.predict_proba(M.vectorise(feats))
            pred = 1 if p >= 0.5 else 0
            lg = langue(_texte(item))
            if y == 1:
                stats[lg][0 if pred == 1 else 1] += 1
                tous[0 if pred == 1 else 1] += 1
            else:
                stats[lg][2 if pred == 1 else 3] += 1
                tous[2 if pred == 1 else 3] += 1
    return stats, tous


def _taux(a: int, b: int) -> str:
    return f"{a / b:.2f} ({a}/{b})" if a + b else "n/a"


def _tableau(titre: str, stats, tous) -> None:
    print(f"\n{titre}")
    print(f"  {'langue':8} {'rappel':14} {'specificite':14}")
    for lg in ("en", "fr"):
        tp, fn, fp, tn = stats.get(lg, [0, 0, 0, 0])
        print(f"  {lg:8} {_taux(tp, tp + fn):14} {_taux(tn, tn + fp):14}")
    tp, fn, fp, tn = tous
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"  {'agrege':8} {_taux(tp, tp + fn):14} {_taux(tn, tn + fp):14}   F1={f1:.4f}")


# --------------------------------------------------------------------------- #
# Score HORS-PLI des positifs francais et de leurs pendants anglais.
# Hors-pli, parce qu'un modele note sur les donnees qui l'ont entraine renvoie
# un chiffre optimiste qui ne dit rien de ce qu'il fera en production.
# --------------------------------------------------------------------------- #
def probabilites_hors_pli(echantillons, cibles, *, k=5, epochs=2000, lr=0.5, l2=1e-3):
    cible_set = set(cibles)
    pos = [s for s in echantillons if s[1] == 1]
    neg = [s for s in echantillons if s[1] == 0]
    rng = random.Random(0)
    rng.shuffle(pos)
    rng.shuffle(neg)

    plis: list[list] = [[] for _ in range(k)]
    for i, it in enumerate(pos):
        plis[i % k].append(it)
    for i, it in enumerate(neg):
        plis[i % k].append(it)

    resultats: dict[str, float] = {}
    for i in range(k):
        entrainement = [s for j, pli in enumerate(plis) if j != i for s in pli]
        modele = M.train(entrainement, epochs=epochs, lr=lr, l2=l2)
        for item, _y in plis[i]:
            if item in cible_set:
                feats = M.extract_features(_wrap(item))
                resultats[item] = modele.predict_proba(M.vectorise(feats))
    return resultats


def scores_cibles(donnees) -> None:
    """Les positifs francais, leurs pendants anglais, et deux benins francais."""
    fr_pos = [t for t in MALICIOUS if langue(t) == "fr"]
    en_pos = [
        t for t in MALICIOUS if langue(t) == "en" and ("receipt" in t.lower() or "Publishes a post" in t)
    ]
    fr_ben = [t for t in BENIGN if langue(t) == "fr"][:2]

    groupes = [
        ("FR malveillant", fr_pos),
        ("EN malveillant", en_pos),
        ("FR benin", fr_ben),
    ]

    def _rapport(titre: str) -> None:
        print(f"\n  {titre}")
        for etiquette, textes in groupes:
            if not textes:
                continue
            probs = probabilites_hors_pli(donnees, textes)
            for t in textes:
                p = probs.get(t)
                marque = "  (hors-pli absent)" if p is None else ""
                valeur = f"{p:.3f}" if p is not None else "n/a"
                print(f"    {etiquette:14} p={valeur}  {t[:64]!r}{marque}")

    _rapport("A. modele complet")
    original = M.extract_features

    def ampute(tool):
        f = original(tool)
        for nom in ENGLISH_DERIVED:
            if nom in f:
                f[nom] = 0.0
        return f

    M.extract_features = ampute
    try:
        _rapport(f"B. ablation : {len(ENGLISH_DERIVED)} features anglaises a zero")
    finally:
        M.extract_features = original


def attributions(donnees) -> None:
    """Quelles features font la decision, sur une paire de traduction et une orpheline.

    Le corpus contient une VRAIE paire : [45] « Envoie une notification de
    facturation » et [46] « Sends a receipt email ». Meme intention, meme
    structure, seule la langue change -- c'est la comparaison controlee que le
    reste de l'issue reclame. [47] est l'orpheline : injection francaise sans
    pendant anglais.

    Modele entraine sur tout le corpus : c'est pour l'interpretation, pas pour la
    mesure. Les probabilites citees ailleurs sont hors-pli.
    """
    cibles = (
        ("EN receipt  [paire]", next(t for t in MALICIOUS if "Sends a receipt email" in t)),
        ("FR notif.   [paire]", next(t for t in MALICIOUS if "Envoie une notification" in t)),
        ("FR contact  [orpheline]", next(t for t in MALICIOUS if "ignorez les instructions" in t)),
    )
    ben_fr = next(t for t in BENIGN if "Request-to-Pay" in t)

    modele = M.train(donnees, epochs=2000)
    print("\nC. attribution des features (modele entraine sur tout le corpus)")
    for etiquette, text in (*cibles, ("FR benin", ben_fr)):
        feats = M.extract_features(_wrap(text))
        x = M.vectorise(feats)
        p = modele.predict_proba(x)
        print(f"\n  {etiquette:24} p={p:.3f}  {text[:52]!r}")
        for nom, contribution in modele.explain(x, limit=5):
            print(f"      {nom:22} valeur={feats.get(nom, 0.0):7.3f}  contribution={contribution:+.3f}")


def _tous():
    return [(t, 1) for t in MALICIOUS] + [(t, 0) for t in BENIGN]


def main() -> int:
    donnees = _tous()
    print(
        f"corpus : {len(MALICIOUS)} malveillants, {len(BENIGN)} benins "
        f"-> {len(donnees)} echantillons, {len(FEATURE_NAMES)} features"
    )

    fr = [(t, y) for t, y in donnees if langue(t) == "fr"]
    print(f"etiquetes francais : {len(fr)}  (dont {sum(1 for _, y in fr if y == 1)} positifs)")
    print("verification des entrees etiquetees francais :")
    for t, y in fr:
        print(f"   [{'MAL' if y else 'BEN'}] {t[:78]!r}")

    original = M.extract_features

    stats, tous = cv_par_langue(donnees)
    _tableau("A. modele complet (31 features)", stats, tous)

    def ampute(tool):
        f = original(tool)
        for nom in ENGLISH_DERIVED:
            if nom in f:
                f[nom] = 0.0
        return f

    M.extract_features = ampute
    try:
        stats2, tous2 = cv_par_langue(donnees)
    finally:
        M.extract_features = original
    _tableau(
        f"B. ablation : {len(ENGLISH_DERIVED)} features anglaises mises a zero",
        stats2,
        tous2,
    )

    scores_cibles(donnees)
    attributions(donnees)
    return 0


if __name__ == "__main__":
    sys.exit(main())
