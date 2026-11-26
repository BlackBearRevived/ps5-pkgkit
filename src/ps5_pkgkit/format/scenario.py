"""``playgo-scenario.json``: the PlayGo scenario document the container carries.

Without it the console logs a missing scenario at launch and games that wait on
PlayGo can sit on a black screen. The generated document names every language
the game supports, in the reference order, with its declared default.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import paramjson

LANGUAGES = (
    "ja-JP", "en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "nl-NL", "pt-PT",
    "ru-RU", "ko-KR", "zh-Hant", "zh-Hans", "fi-FI", "sv-SE", "da-DK", "no-NO",
    "pl-PL", "pt-BR", "en-GB", "tr-TR", "es-419", "ar-AE", "fr-CA", "cs-CZ",
    "hu-HU", "el-GR", "ro-RO", "th-TH", "vi-VN", "id-ID", "uk-UA",
)


@dataclass(frozen=True, slots=True)
class GameLanguages:
    supported: tuple[str, ...]
    default: str


def _known(code: str | None) -> str | None:
    return code if code in LANGUAGES else None


def game_languages(scenario: bytes, param_json: bytes) -> GameLanguages | None:
    """The game's own languages and default, from its stale scenario or its param.json."""
    parsed = paramjson.parse(scenario) if scenario else None
    if isinstance(parsed, dict):
        supported: list[str] = []
        listed = parsed.get("chunkSupportedLanguages")
        if isinstance(listed, list):
            for code in listed:
                known = _known(code) if isinstance(code, str) else None
                if known and known not in supported:
                    supported.append(known)
        if supported:
            default = supported[0]
            for key in ("chunkDefaultLanguage", "scenarioDefaultLanguage"):
                candidate = _known(parsed.get(key)) if isinstance(parsed.get(key), str) else None
                if candidate and candidate in supported:
                    default = candidate
                    break
            return GameLanguages(tuple(supported), default)
    params = paramjson.parse(param_json)
    if isinstance(params, dict):
        localized = params.get("localizedParameters")
        if isinstance(localized, dict):
            default = _known(localized.get("defaultLanguage")) \
                if isinstance(localized.get("defaultLanguage"), str) else None
            if default:
                return GameLanguages(LANGUAGES, default)
    return None


def scenario_json(supported: tuple[str, ...], default: str) -> bytes:
    names = ",".join(
        f'"{code}":{{"title":"Scenario #0","description":"Scenario #0"}}'
        for code in supported)
    languages = ",".join(f'"{code}"' for code in supported)
    text = (
        f'{{"scenarioCount":1,"scenarioDefaultId":0,'
        f'"scenarioDefaultLanguage":"{default}",'
        f'"scenarios":[{{"id":0,"type":"playmode",{names}}}],'
        f'"chunkDefaultLanguage":"{default}",'
        f'"chunkSupportedLanguages":[{languages}]}}'
    )
    return text.encode("utf-8")


def build(scenario: bytes, param_json: bytes, language: str | None = None) -> bytes:
    """The document for a package: a chosen language, else the game's own, else all of them."""
    chosen = _known(language)
    if chosen:
        return scenario_json((chosen,), chosen)
    game = game_languages(scenario, param_json)
    if game is not None:
        return scenario_json(game.supported, game.default)
    return scenario_json(LANGUAGES, "en-US")
