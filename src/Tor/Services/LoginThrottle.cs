// Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
// SPDX-License-Identifier: MIT
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Tor.Services;

/// <summary>
/// Counts failed sign-ins per username and per client address in a fixed window. In memory, per
/// process: an app pool recycle resets it, AD lockout still applies. Keys are hashed (bounded length
/// whatever was typed), the table has a hard cap, and an attempt is checked and counted in one step.
/// </summary>
public sealed class LoginThrottle
{
    /// <summary>The most windows kept. When full, expired windows go first, then the oldest tenth.</summary>
    public const int MaxEntries = 50_000;

    private readonly Dictionary<string, Window> _failures = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();
    private readonly TorOptions _options;
    private readonly TimeProvider _time;

    public LoginThrottle(IOptions<TorOptions> options, TimeProvider time)
    {
        _options = options.Value;
        _time = time;
    }

    // a setting below 1 is a configuration error (refused for directory sign-ins); here it never switches the throttle off
    private TimeSpan Length => TimeSpan.FromMinutes(Math.Max(1, _options.FailureWindowMinutes));

    private int UserLimit => Math.Max(1, _options.MaxFailuresPerUser);

    private int ClientLimit => Math.Max(1, _options.MaxFailuresPerClient);

    public bool IsBlocked(string userKey, string clientKey)
    {
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            return Count(UserKey(userKey), now) >= UserLimit || Count(ClientKey(clientKey), now) >= ClientLimit;
        }
    }

    public void RecordFailure(string userKey, string clientKey)
    {
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            Add(UserKey(userKey), now);
            Add(ClientKey(clientKey), now);
        }
    }

    // a good sign-in clears the username, not the client address (one client may try many names)
    public void RecordSuccess(string userKey)
    {
        lock (_lock)
        {
            _failures.Remove(UserKey(userKey));
        }
    }

    /// <summary>
    /// Checks and counts the attempt in one step, so parallel attempts cannot pass the limit: null when blocked.
    /// The attempt then stands as a failure unless it is <see cref="Succeeded"/> or <see cref="Release"/>d.
    /// </summary>
    public Attempt? TryBegin(string userKey, string clientKey)
    {
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            var (user, client) = (UserKey(userKey), ClientKey(clientKey));
            if (Count(user, now) >= UserLimit || Count(client, now) >= ClientLimit)
            {
                return null;
            }

            return new Attempt(user, Add(user, now), client, Add(client, now));
        }
    }

    /// <summary>A good sign-in: the username's count is cleared and the client address gets its attempt back.</summary>
    public void Succeeded(Attempt attempt)
    {
        lock (_lock)
        {
            _failures.Remove(attempt.UserKey);
            GiveBack(attempt.ClientKey, attempt.ClientWindow);
        }
    }

    /// <summary>An outcome that is not the user's fault (the domain could not be reached): the attempt is not counted.</summary>
    public void Release(Attempt attempt)
    {
        lock (_lock)
        {
            GiveBack(attempt.UserKey, attempt.UserWindow);
            GiveBack(attempt.ClientKey, attempt.ClientWindow);
        }
    }

    private static string UserKey(string key) => "u:" + Hash(key);

    private static string ClientKey(string key) => "c:" + Hash(key);

    private static string Hash(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    private int Count(string key, DateTimeOffset now)
    {
        if (!_failures.TryGetValue(key, out var window))
        {
            return 0;
        }

        if (now - window.Start >= Length)
        {
            _failures.Remove(key);
            return 0;
        }

        return window.Count;
    }

    // counts one failure; returns the start of the window it was counted in
    private DateTimeOffset Add(string key, DateTimeOffset now)
    {
        if (_failures.TryGetValue(key, out var window) && now - window.Start < Length)
        {
            _failures[key] = window with { Count = window.Count + 1 };
            return window.Start;
        }

        if (window is null)
        {
            MakeRoom(now);
        }

        _failures[key] = new Window(now, 1);
        return now;
    }

    // takes back one count, only from the window it was counted in
    private void GiveBack(string key, DateTimeOffset windowStart)
    {
        if (_failures.TryGetValue(key, out var window) && window.Start == windowStart)
        {
            if (window.Count <= 1)
            {
                _failures.Remove(key);
            }
            else
            {
                _failures[key] = window with { Count = window.Count - 1 };
            }
        }
    }

    // bounded memory: when full, drop expired windows, then the oldest tenth
    private void MakeRoom(DateTimeOffset now)
    {
        if (_failures.Count < MaxEntries)
        {
            return;
        }

        foreach (var (key, window) in _failures)
        {
            if (now - window.Start >= Length)
            {
                _failures.Remove(key);
            }
        }

        if (_failures.Count < MaxEntries)
        {
            return;
        }

        foreach (var key in _failures.OrderBy(e => e.Value.Start).Take(MaxEntries / 10).Select(e => e.Key).ToList())
        {
            _failures.Remove(key);
        }
    }

    /// <summary>One sign-in attempt in progress: the keys it was counted under, and in which windows.</summary>
    public sealed record Attempt(string UserKey, DateTimeOffset UserWindow, string ClientKey, DateTimeOffset ClientWindow);

    private sealed record Window(DateTimeOffset Start, int Count);
}
