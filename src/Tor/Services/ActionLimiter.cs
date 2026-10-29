// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;

namespace Tor.Services;

/// <summary>
/// Counts attempts of an account action per key (action and user) in a fixed window; every attempt
/// that reaches the directory counts, successful or not. In memory, per process.
/// </summary>
public sealed class ActionLimiter
{
    private const int MaxEntries = 10_000;

    private readonly ConcurrentDictionary<string, Window> _attempts = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public ActionLimiter(TimeProvider time) => _time = time;

    /// <summary>Records an attempt and says whether it is allowed (false once <paramref name="limit"/> is used up).</summary>
    public bool TryAcquire(string key, int limit, TimeSpan window)
    {
        var now = _time.GetUtcNow();
        Prune(now, window);

        var allowed = false;
        _attempts.AddOrUpdate(
            key,
            _ =>
            {
                allowed = limit > 0;
                return new Window(now, 1);
            },
            (_, current) =>
            {
                if (now - current.Start >= window)
                {
                    allowed = limit > 0;
                    return new Window(now, 1);
                }

                allowed = current.Count < limit;
                return allowed ? current with { Count = current.Count + 1 } : current;
            });

        return allowed;
    }

    private void Prune(DateTimeOffset now, TimeSpan window)
    {
        if (_attempts.Count < MaxEntries)
        {
            return;
        }

        foreach (var (key, entry) in _attempts)
        {
            if (now - entry.Start >= window)
            {
                _attempts.TryRemove(key, out _);
            }
        }
    }

    private sealed record Window(DateTimeOffset Start, int Count);
}
