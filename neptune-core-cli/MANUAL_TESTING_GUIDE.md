# Manual RPC Testing Guide

## Prerequisites

1. **neptune-core must be running** (the main blockchain daemon)
2. **neptune-cli binary must be built** (`cargo build --release`)

## Step-by-Step Testing

### 1. Get Authentication Cookie

```bash
# Get the authentication cookie
./target/release/neptune-cli --get-cookie
```

**Copy the cookie value** - you'll need it for all RPC calls.

### 2. Start RPC Server

```bash
# Start the HTTP JSON-RPC server on port 9800
./target/release/neptune-cli --rpc-mode --rpc-port 9800
```

The server will start and listen on `http://localhost:9800`

### 3. Test Individual Endpoints

#### Test Network Information

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "network", "id": 1}'
```

#### Test Block Height

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "block_height", "id": 2}'
```

#### Test Confirmed Balance

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "confirmed_available_balance", "id": 3}'
```

#### Test Unconfirmed Balance

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "unconfirmed_available_balance", "id": 4}'
```

#### Test Peer Information

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "peer_info", "id": 5}'
```

#### Test Mempool Transaction Count

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "mempool_tx_count", "id": 6}'
```

### 4. Test the Main Dashboard Endpoint ⭐

This is the **most important endpoint** for your wallet:

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "dashboard_overview_data", "id": 7}'
```

**Expected Response Structure:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tip_digest": "abc123...",
    "tip_header": {
      "height": 12345,
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "syncing": false,
    "confirmed_available_balance": "1000000",
    "confirmed_total_balance": "1000000",
    "unconfirmed_available_balance": "0",
    "unconfirmed_total_balance": "0",
    "mempool_size": 1024,
    "mempool_total_tx_count": 5,
    "mempool_own_tx_count": 0,
    "peer_count": 3,
    "max_num_peers": 50,
    "mining_status": "active",
    "proving_capability": "enabled",
    "confirmations": "100",
    "cpu_temp": 45.5
  },
  "id": 7
}
```

### 5. Test Wallet Operations

#### Get Wallet Status

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "wallet_status", "id": 8}'
```

#### Get Next Receiving Address

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "next_receiving_address", "id": 9}'
```

#### Get Transaction History

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "history", "id": 10}'
```

### 6. Test Validation Endpoints

#### Validate Address

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "validate_address", "params": {"address": "nolgam1lf8vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s"}, "id": 11}'
```

#### Validate Amount

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "validate_amount", "params": {"amount": "1000"}, "id": 12}'
```

## Expected Response Format

All successful responses follow this format:

```json
{
  "jsonrpc": "2.0",
  "result": <actual_data>,
  "id": <request_id>
}
```

Error responses follow this format:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32603,
    "message": "Internal error"
  },
  "id": <request_id>
}
```

## Troubleshooting

### Common Issues

1. **"Connection refused"**
   - Make sure neptune-core is running
   - Check if RPC server started successfully

2. **"Invalid cookie"**
   - Get a fresh cookie with `./target/release/neptune-cli --get-cookie`
   - Make sure neptune-core is running when getting the cookie

3. **"Method not found"**
   - Check the method name spelling
   - Make sure you're using the correct JSON-RPC format

4. **"Internal error"**
   - Check neptune-core logs
   - Make sure neptune-core is fully synced

### Quick Verification

Test basic connectivity:

```bash
curl -s http://localhost:9800
```

If the server is running, you should get a response (even if it's an error about missing JSON-RPC format).

## Next Steps

Once you've verified the RPC endpoints are working:

1. **Update your wallet's blockchain-service.ts** to use these endpoints
2. **Implement cookie-based authentication** in your wallet
3. **Use `dashboard_overview_data`** as your primary endpoint for comprehensive wallet state
4. **Test the integration** with your wallet UI
