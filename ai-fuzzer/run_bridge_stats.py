"""
run_bridge_stats.py — серия прогонов fuzzer_bridge.py для сбора
статистики стабильности LLM-фаззера (Фаза 6.5).

ОБНОВЛЕНО: fuzzer_bridge.run_fuzzer() теперь сам по себе каскад
(blind -> guided), поэтому у каждого прогона три возможных исхода:
    "blind"      — баг найден САМОСТОЯТЕЛЬНО, без подсказки
    "guided"     — баг найден ТОЛЬКО после подсказки
    "not_found"  — баг не найден даже с подсказкой

Раньше при падении с исключением текст ошибки печатался в консоль и
терялся — прогон просто помечался как "не найдено", что делало
инфраструктурный сбой (например, Ollama вернула пустой ответ)
неотличимым от настоящей неудачи модели. Теперь текст ошибки
сохраняется в "error" у каждого прогона.

Запуск:
    source venv/bin/activate
    python run_bridge_stats.py          # 30 прогонов по умолчанию
    python run_bridge_stats.py 50       # 50 прогонов
"""

import json
import math
import sys
import time

import fuzzer_bridge

N_RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 30


def wilson_interval(successes: int, n: int, z: float = 1.96):
    """
    Доверительный интервал Уилсона — точнее обычной нормальной
    аппроксимации при небольших n, особенно когда доля успеха близка
    к 0 или к 1.
    """
    if n == 0:
        return (0.0, 0.0)
    p_hat = successes / n
    denom = 1 + z**2 / n
    centre = p_hat + z**2 / (2 * n)
    adj = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * n)) / n)
    lower = (centre - adj) / denom
    upper = (centre + adj) / denom
    return (max(0.0, lower), min(1.0, upper))


def median(values):
    if not values:
        return None
    s = sorted(values)
    mid = len(s) // 2
    if len(s) % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2
    return s[mid]


def main():
    print(f"\n{'='*60}")
    print(f"  СЕРИЯ ПРОГОНОВ fuzzer_bridge.py (каскад blind->guided): N = {N_RUNS}")
    print(f"{'='*60}\n")

    results = []

    for run_idx in range(1, N_RUNS + 1):
        print(f"\n### Прогон {run_idx}/{N_RUNS} ###")
        start = time.monotonic()
        error = None
        try:
            report = fuzzer_bridge.run_fuzzer()
        except Exception as e:
            report = None
            error = str(e)   # причина падения теперь не теряется
            print(f"❌ Прогон упал с исключением: {error}")
        elapsed = time.monotonic() - start

        # report всегда словарь (см. _save_not_found), либо None если
        # само исключение прервало выполнение раньше
        if report is None and error is None:
            stage = "not_found"
            iterations = None
        elif report is None:
            stage = "infra_error"
            iterations = None
        else:
            stage = report.get("stage", "not_found")
            iterations = report.get("found_on_iteration")

        results.append({
            "run": run_idx,
            "stage": stage,                 # "blind" / "guided" / "not_found" / "infra_error"
            "found_on_iteration": iterations,
            "elapsed_seconds": round(elapsed, 1),
            "error": error,
        })

        status_map = {
            "blind":  f"✅ найден БЕЗ подсказки на итерации {iterations}",
            "guided": f"✅ найден С подсказкой на итерации {iterations}",
            "not_found": "❌ не найден даже с подсказкой",
            "infra_error": f"⚠️ инфраструктурная ошибка: {error}",
        }
        print(f"### Прогон {run_idx}/{N_RUNS} завершён за {elapsed:.1f} сек — {status_map[stage]} ###")

        # сохраняем промежуточный прогресс — если серия прервётся,
        # данные не потеряются
        with open("build/bridge_stability_stats.json", "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    # ── итоговая статистика ──────────────────────────────────────
    n = len(results)
    found_blind  = sum(1 for r in results if r["stage"] == "blind")
    found_guided = sum(1 for r in results if r["stage"] == "guided")
    not_found    = sum(1 for r in results if r["stage"] == "not_found")
    infra_errors = sum(1 for r in results if r["stage"] == "infra_error")

    # доля "нашли хоть как-то" (blind ИЛИ guided) — общая находимость бага
    found_total = found_blind + found_guided
    ci_blind_low, ci_blind_high = wilson_interval(found_blind, n)
    ci_total_low, ci_total_high = wilson_interval(found_total, n)

    iters_blind  = [r["found_on_iteration"] for r in results if r["stage"] == "blind"]
    iters_guided = [r["found_on_iteration"] for r in results if r["stage"] == "guided"]
    times = [r["elapsed_seconds"] for r in results]

    summary = {
        "n_runs": n,
        "found_without_hint": found_blind,
        "found_without_hint_pct": round(found_blind / n * 100, 1),
        "wilson_95ci_without_hint_pct": [round(ci_blind_low * 100, 1), round(ci_blind_high * 100, 1)],
        "found_with_hint_only": found_guided,
        "found_with_hint_only_pct": round(found_guided / n * 100, 1),
        "not_found_even_with_hint": not_found,
        "not_found_pct": round(not_found / n * 100, 1),
        "infra_errors": infra_errors,
        "found_total_pct": round(found_total / n * 100, 1),
        "wilson_95ci_total_pct": [round(ci_total_low * 100, 1), round(ci_total_high * 100, 1)],
        "median_iterations_blind": median(iters_blind),
        "median_iterations_guided": median(iters_guided),
        "median_seconds_per_run": median(times),
        "total_seconds": round(sum(times), 1),
        "runs": results,
    }

    with open("build/bridge_stability_stats.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print("  ИТОГОВАЯ СТАТИСТИКА")
    print(f"{'='*60}")
    print(f"  Прогонов всего:                    {n}")
    print(f"  Найдено БЕЗ подсказки:             {found_blind} ({summary['found_without_hint_pct']}%) "
          f"[95% ДИ: {summary['wilson_95ci_without_hint_pct']}%]")
    print(f"  Найдено ТОЛЬКО с подсказкой:       {found_guided} ({summary['found_with_hint_only_pct']}%)")
    print(f"  Не найдено даже с подсказкой:      {not_found} ({summary['not_found_pct']}%)")
    print(f"  Инфраструктурные ошибки:           {infra_errors}")
    print(f"  Найдено ВСЕГО (blind+guided):      {found_total} ({summary['found_total_pct']}%) "
          f"[95% ДИ: {summary['wilson_95ci_total_pct']}%]")
    print(f"  Медиана итераций (blind):          {summary['median_iterations_blind']}")
    print(f"  Медиана итераций (guided):         {summary['median_iterations_guided']}")
    print(f"  Медианное время прогона:           {summary['median_seconds_per_run']:.1f} сек")
    print(f"  Суммарное время серии:             {summary['total_seconds']:.1f} сек ({summary['total_seconds']/60:.1f} мин)")
    print(f"\n✅ Полная статистика сохранена: build/bridge_stability_stats.json")


if __name__ == "__main__":
    import os
    os.makedirs("build", exist_ok=True)
    main()