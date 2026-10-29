// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace Tor.Services;

/// <summary>
/// Counts failed sign-ins per username and per client address in a fixed window. In memory, per
/// process: an app pool recycle resets it, AD lockout still applies.
/// </summary>
public sealed class LoginThrottle
{
    private const int MaxEntries = 10_000;

    private readonly ConcurrentDictionary<string, Window> _failures = new(StringComparer.Ordinal);
    private readonly TorOptions _options;
    private readonly TimeProvider _time;

    public LoginThrottle(IOptions<TorOptions> options, TimeProvider time)
    {
        _options = options.Value;
        _time = time;
    }

    private TimeSpan Length => TimeSpan.FromMinutes(_options.FailureWindowMinutes);

    public bool IsBlocked(string userKey, string clientKey) =>
        Count("u:" + userKey) >= _options.MaxFailuresPerUser || Count("c:" + clientKey) >= _options.MaxFailuresPerClient;

    public void RecordFailure(string userKey, string clientKey)
    {
        Prune();
        Add("u:" + userKey);
        Add("c:" + clientKey);
    }

    // a good sign-in clears the username, not the client address (one client may try many names)
    public void RecordSuccess(string userKey) => _failures.TryRemove("u:" + userKey, out _);

    private int Count(string key)
    {
        if (!_failures.TryGetValue(key, out var window))
        {
            return 0;
        }

        if (_time.GetUtcNow() - window.Start >= Length)
        {
            _failures.TryRemove(key, out _);
            return 0;
        }

        return window.Count;
    }

    private void Add(string key)
    {
        var now = _time.GetUtcNow();
        _failures.AddOrUpdate(
            key,
            _ => new Window(now, 1),
            (_, window) => now - window.Start >= Length ? new Window(now, 1) : window with { Count = window.Count + 1 });
    }

    // bounded memory: drop expired windows when the table grows
    private void Prune()
    {
        if (_failures.Count < MaxEntries)
        {
            return;
        }

        var now = _time.GetUtcNow();
        foreach (var (key, window) in _failures)
        {
            if (now - window.Start >= Length)
            {
                _failures.TryRemove(key, out _);
            }
        }
    }

    private sealed record Window(DateTimeOffset Start, int Count);
}
