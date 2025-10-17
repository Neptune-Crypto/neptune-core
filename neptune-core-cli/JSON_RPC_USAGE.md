# Neptune CLI JSON-RPC Usage Guide

This document provides a complete guide for using the neptune-cli RPC server to interact with neptune-core via HTTP JSON-RPC.

## Quick Start

### 1. Start neptune-core

```bash
neptune-core --peer [ip_address:port] --compose --guess
```

### 2. Get Authentication Cookie

```bash
neptune-cli --get-cookie
```

### 3. Start neptune-cli RPC Server

```bash
neptune-cli --rpc-mode --rpc-port 9800
```

### 4. Make RPC Requests

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_VALUE" \
  -d '{"jsonrpc": "2.0", "method": "block_height", "params": {}, "id": 1}'
```

## Authentication

All RPC methods require authentication via a cookie. Get your cookie using:

```bash
neptune-cli --get-cookie
```

This will output:

```
Authentication cookie for RPC access:
Cookie: neptune-cli=f9dad1f82f204e287de7319189e7309acc5d3a5db229553ffd5e6e23aba0827b

Use this cookie in your HTTP requests:
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=f9dad1f82f204e287de7319189e7309acc5d3a5db229553ffd5e6e23aba0827b" \
  -d '{"jsonrpc": "2.0", "method": "block_height", "params": {}, "id": 1}'
```

## Available RPC Methods

### Blockchain Information

#### `block_height`

Get current blockchain height.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "block_height",
  "params": {},
  "id": 1
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "8783",
  "id": 1
}
```

#### `network`

Get current network type.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "network",
  "params": {},
  "id": 2
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "Main",
  "id": 2
}
```

#### `confirmations`

Get confirmation count.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "confirmations",
  "params": {},
  "id": 3
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "6",
  "id": 3
}
```

### Wallet Operations

#### `confirmed_available_balance`

Get confirmed wallet balance.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "confirmed_available_balance",
  "params": {},
  "id": 4
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "1000000000",
  "id": 4
}
```

#### `unconfirmed_available_balance`

Get unconfirmed wallet balance.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "unconfirmed_available_balance",
  "params": {},
  "id": 5
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "0",
  "id": 5
}
```

#### `wallet_status`

Get wallet status information.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_status",
  "params": {},
  "id": 6
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "{\"is_synced\":true,\"height\":8783}",
  "id": 6
}
```

#### `dashboard_overview_data`

Get comprehensive dashboard overview data (primary endpoint for UI).

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dashboard_overview_data",
  "params": {},
  "id": 7
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "block_height": "8783",
    "network": "Main",
    "confirmed_available_balance": "1000000000",
    "unconfirmed_available_balance": "0",
    "wallet_status": "{\"is_synced\":true,\"height\":8783}",
    "peer_count": 5,
    "mempool_tx_count": 0,
    "sync_percentage": 100.0
  },
  "id": 7
}
```

#### `next_receiving_address`

Generate next receiving address.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "next_receiving_address",
  "params": { "key_type": "Generation" },
  "id": 7
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "nolgam1643esgrlpu02a0twg5gv4mja88p5n7esmsqc0a6qjk7jkw20le4cpa0skmrrfkwq0aea3w9892rg2dzjmgzq7s2v4j0fg82kt02y5s3vgmkfencktzvtsk73dkkv7pqh9x0ecmyen4wh7vsqurwnhc20ujncdfzulnjkq2ftr50767z5zvzgpemsjujfmzdr906n0ma5tr6dj45uk0c2jx02p6r578g39s4504m7pkfgvwfuwk3aml0y5l3wsxz28jrl7a7jkt4r5ern0dv9ar0qpswp7w0vgjsrwpgec78z2pgm3300688jjmeyqfz6w7xx06e0v67jqcqdjne5v6fmjeunyxgvaq5yjp9u4vlwqy52avw4xu2a4jdsgr0nm47vmkzxe456ryke34pfdw3645wpz3f7jy0s2p0hv859y9t5ygyr540cp2cm3ex9j0rewkr6arthct0jsq50y2j6x8xjq2wsd7kpzsgx24gk7pyeyk300jqtadqg6uf9sn7z5v3ytkzqzv7zlfkmxeg6e4sks59fzf4mmpzmtrytgsyj98fu78t6kq67yclpmhnce5pypffrzhvqnzkg0dlw6fxweat2kh7h5ljcnxu3v53je69pac4nwe2frn33w3knajj66wa2y6le67k965nyeygpscj0nwdc8l7902rskhjuqnjerg7kaplkt0fhzcdfp7makrhuhjy69psz8hy5efmwav5afyqrnl87cyrca3ycxd00lu3e2epyme388f78j9gzzkmftg9rqw4ew5su2gfqfw4zc2h4hhu80d75seprne8efuxxj5p2py6xeg5d4fsshmdmjlehpc89p585dntlv3r8wx2vvk3dd0fwuwtzpr5sfp5zmyvusapfx50kzl56pmwykuua7k05fqalj5ha2tj9pjwvpsmen2grhl4j3v2w7zkjslttnfew28jzzdmhwnx0hxq99p5tnmcj5kc090rrel302pdfqjwcvtc5280urgckgtvv5680wuneyy4hr3ryvse3kwacuy86a8gkxgg0tmf6xphthhy9nn66d9vvqn8g46mnt6zmfgm0pln8c8utnacfmha8s076qhuz2d6q2gcn93m7ausuxu9axzzkrgml2jckzr3lurm5zqjcz00etflm6xmcpk6e4tp234jvfxk9n9k0rcwd0ztmgskg3q0ncmh023frsu8ujnclrluajykf26axs3z455rcem2gnxyck5ejgglfmzuq2jjxk3zlwxrnc522qdyer07d6t9hjjk9rx46qy3wwtgrqlqa889ws32hvgsxk5xwqwlcs2cmcyx9as639ysfmyxfaqcsmgr444mdjq3fjvx5frlsej8t255rp7xdjxg892c0vrpustrmz4aqftj2jcf5gafayaxwrpzqqlgzwg4p9rt5pwyle8syr5w8rrwq5wcm80py8nk42ts36zwm0ad25fy7u5hce233nplhgpkg6qkcv7rm6rkn6pz99tx54mrngz8xh4kn7exdqqj0zvmtea36cq5pt6mjc8t7zundjvlula33uqmgwzs5j87wdc2cd4xn7cks7ywser0zgxkdyhrcdygev2c7s7wkdemauvh705khp37kklk8facxfusycpy9mydcyjzldjyrduw7cgqft60a65tdgrdcw5j9950ayyd4p97wv6c9976z5wlwuc0ueslv7xtsdvfm7gptt3p3k2ahtygw8e5f4tgkhe4n97rh0ttwmjtkell0qn9y69yrfk5pw3y5vfes63l60s5zwulyxwynvljlk9u5axxd9fz2jjm9q2jhyz8c6yqa4avs4rpzxkgf2xkl08hzk6tqzalz3hghf00q7y590m283ujc64w983w0fc8x07y2prjl27fcpx86h73maw653xws66gfunx4wf7nf2h6j2pu9yfpadukv43gc44f006l7psfmf6rp2ar0jlk8rp3zmc9wvu6pruustukfpn8ldy8vgqw0j7ag5ndhkna5l4nvw55fem39h35r5ppf9rxzvjq57jr4sxyvp0rnk62pxa33lx2lt6e3gzreetsgsxnv5gmk3je9q6ucknfl440f7yhnyepzhmphr0zfk3mz52jnpfek34sllxmysx2vznzn3gtnj479yzpqw0pqps70pmpd9mpkaxx7whklrf26n3nm6raxrth2gvrhhjckuwphzkr03jf7cvpt7ah3qwnrn09uwp4nf6egvxzm6rsq2lpa9a792uhzxd47lcykynzrr9spfj5z26spz606jewkdahkhzcqwl7xcrtzy0zu8hwp9vjwz5g7q3r9rfqk9u0au4njkqqgmgt5lr09gfj40sf9682wwfqwjkdsqmesl233a2njxr70t4q4tyjt5v90vnc6yrxx4c6x8g7z6hhqhyh44dd7wyktap0vrpmy06q4zk8nj9pn20a34vxjcnnjak2w5e9rg584n3wh5y40pvnzxlc9tqagsf7x0g8xkn6k66z9ehykqcjctr6y65xavr4e0l4dz6hunyhkzg26xqm9r34c65jdmh4n8ee3qlgkfys9mreuzsay9w8lytck4k473q7d0waeyhcjm67e0lm58545yc9h5xmvwrpfy7hkke0j3yne05pxvz062fn0l0qrr5n94ps08flztaz4hdhs7yg9wum8qf87v7kgscfn83cwu4ytl459z7x6pycm4jn7d6tq0n4hc3dylzz294acq6ms5vmjnl4kezwcrcskgvckh492gjshgdq8d73anyhjvy7v34ykanvf0jj9epg3uk2umu3fddstuk56ze9w3u3z5ty3y66mphpv8256lgd5aywpzuv8v4gg8hkwgzppxvx3kje48n4rkcqelyg6rt6fhqpf6trn7tcvg04hmzvjtw3f9fxmftsqqqg9c933c3g26xz37uee3ewqtdck2dquj96anmg54um9e2dr6j83eltyz7ndwt2twhu6277akgvhkhnu6a8t3uw3q665zkpwuhgj2mcp8w63ml0cg5z2gh8hy0n6gt7wdakk5xpe8yrm23jj5zr9ngflmmtr2rcgatru445486ya29zxpw526ph3ffwuwqjlzm60unyc8peyjjhn3k9pl2e348pcletpa39eqmj30tg8a35hf9u6gxtq75xz9xgtp3pxsqw5fkrlmlcyu0udgpxdgnwqyqnyhgp0g4srtakfflju4d7xus4hx5dlkw8vmv8g0y8vx4xtf2f8h5w26sqqu694lxer6sz20y285vskdc0hjhfg5rfe28228p75qj5vq3ar57pqdnlvr8uqk2q684w24gssda2075vcp7q02hs0mp0salmyyh4h3sgsp03zx2y2e0au9t9u8hgpl33elnytx3hytr28fwza76kz8ka3lk5kl4zwsyunp5u9lyfamulx83vkje",
  "id": 7
}
```

### Standalone Wallet Methods

#### `generate_wallet`

Generate a new wallet.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "generate_wallet",
  "params": { "network": "Main" },
  "id": 8
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "Wallet generated successfully at: /path/to/wallet.dat",
  "id": 8
}
```

#### `export_seed_phrase`

Export wallet seed phrase.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "export_seed_phrase",
  "params": { "network": "Main" },
  "id": 9
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "id": 9
}
```

#### `import_seed_phrase`

Import wallet from seed phrase.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "import_seed_phrase",
  "params": {
    "seed_phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "network": "Main"
  },
  "id": 10
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "Wallet imported successfully",
  "id": 10
}
```

### Mining Operations

#### `pause_miner`

Pause the miner.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "pause_miner",
  "params": {},
  "id": 11
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "Miner paused successfully",
  "id": 11
}
```

#### `restart_miner`

Restart the miner.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "restart_miner",
  "params": {},
  "id": 12
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": "Miner restarted successfully",
  "id": 12
}
```

## Error Handling

### Authentication Error

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Authentication required"
  },
  "id": 1
}
```

### Method Not Found

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found"
  },
  "id": 1
}
```

### Invalid Parameters

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params"
  },
  "id": 1
}
```

## Complete Example Workflow

1. **Start neptune-core:**

   ```bash
   neptune-core --peer 51.15.139.238:9798 --compose --guess
   ```

2. **Get authentication cookie:**

   ```bash
   neptune-cli --get-cookie
   ```

3. **Start RPC server:**

   ```bash
   neptune-cli --rpc-mode --rpc-port 9800
   ```

4. **Test connection:**
   ```bash
   curl -X POST http://localhost:9800 \
     -H "Content-Type: application/json" \
     -H "Cookie: neptune-cli=YOUR_COOKIE_VALUE" \
     -d '{"jsonrpc": "2.0", "method": "block_height", "params": {}, "id": 1}'
   ```

## Security Notes

- Always use HTTPS in production environments
- Keep your authentication cookie secure
- The cookie provides full access to your wallet
- Never share your cookie with untrusted parties
- Use the `--get-cookie` command only when needed

## Troubleshooting

### Connection Refused

- Ensure neptune-core is running on port 9799
- Check that neptune-cli RPC server is running on your specified port

### Authentication Failed

- Run `neptune-cli --get-cookie` to get a fresh cookie
- Ensure the cookie is correctly formatted in the HTTP header

### Method Not Found

- Verify the method name is correct
- Check that neptune-core supports the requested method
