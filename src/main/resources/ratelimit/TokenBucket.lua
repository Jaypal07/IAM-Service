-- KEYS[1] = rate limit key
-- ARGV[1] = capacity
-- ARGV[2] = refill_per_second
-- ARGV[3] = current_time_seconds

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Defensive: invalid configs never block
if capacity == nil or capacity <= 0 then
    return 1
end

local data = redis.call("HMGET", key, "tokens", "timestamp")

local tokens = tonumber(data[1])
local last_timestamp = tonumber(data[2])

-- First request initialization
if tokens == nil or last_timestamp == nil then
    tokens = capacity
    last_timestamp = now
end

-- Refill only if enabled
if refill_rate ~= nil and refill_rate > 0 then
    local elapsed = now - last_timestamp
    if elapsed > 0 then
        local refill = elapsed * refill_rate
        tokens = math.min(capacity, tokens + refill)
        last_timestamp = now
    end
end

-- Block if empty
if tokens < 1 then
    redis.call("HMSET", key,
        "tokens", tokens,
        "timestamp", last_timestamp
    )

    -- Stable TTL
    if refill_rate ~= nil and refill_rate > 0 then
        redis.call("EXPIRE", key, math.ceil(capacity / refill_rate))
    else
        redis.call("EXPIRE", key, 3600)
    end

    return 0
end

-- Consume token
tokens = tokens - 1

redis.call("HMSET", key,
    "tokens", tokens,
    "timestamp", last_timestamp
)

-- Stable TTL again
if refill_rate ~= nil and refill_rate > 0 then
    redis.call("EXPIRE", key, math.ceil(capacity / refill_rate))
else
    redis.call("EXPIRE", key, 3600)
end

return 1
