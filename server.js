const http = require('http');
const { exec } = require('child_process');
const dns  = require('dns').promises;
const net  = require('net');
const os   = require('os');

function getLocalSubnet() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                const parts = iface.address.split('.');
                return { subnet: `${parts[0]}.${parts[1]}.${parts[2]}`, ownIp: iface.address, mac: iface.mac };
            }
        }
    }
    return null;
}

function getArpTable() {
    return new Promise((resolve) => {
        exec('arp -a', (err, stdout) => {
            if (err) return resolve([]);
            const devices = [];
            for (const line of stdout.split('\n')) {
                const winMatch  = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([\w-]{17})\s+(\w+)/);
                const unixMatch = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\w:]{17})/);
                const match = winMatch || unixMatch;
                if (!match) continue;
                const ip   = match[1];
                const mac  = match[2].replace(/-/g, ':').toLowerCase();
                const type = winMatch ? match[3] : 'dynamic';
                if (mac === 'ff:ff:ff:ff:ff:ff' || mac === '00:00:00:00:00:00') continue;
                if (type === 'invalid') continue;
                devices.push({ ip, mac });
            }
            resolve(devices);
        });
    });
}

function pingSubnet(subnet) {
    return new Promise((resolve) => {
        const isWin = process.platform === 'win32';
        let done = 0;
        for (let i = 1; i <= 254; i++) {
            const ip  = `${subnet}.${i}`;
            const cmd = isWin ? `ping -n 1 -w 200 ${ip}` : `ping -c 1 -W 1 ${ip}`;
            exec(cmd, () => { if (++done === 254) resolve(); });
        }
    });
}

async function resolveHostname(ip) {
    try {
        const hostnames = await dns.reverse(ip);
        if (hostnames && hostnames.length > 0) {
            const full = hostnames[0].replace(/\.$/, '');
            return full.split('.')[0] || full;
        }
    } catch (_) {}

    return new Promise((resolve) => {
        const cmd = process.platform === 'win32' ? `nslookup ${ip}` : `host ${ip}`;
        exec(cmd, { timeout: 2000 }, (err, stdout) => {
            if (err || !stdout) return resolve(null);
            const m = stdout.match(/name\s*=\s*([^\s]+)/i) ||
                      stdout.match(/pointer\s+([^\s]+)/i)  ||
                      stdout.match(/domain name pointer\s+([^\s]+)/i);
            if (m) {
                const name = m[1].replace(/\.$/, '').split('.')[0];
                return resolve(name || null);
            }
            resolve(null);
        });
    });
}

const PORT_HINTS = [
    { port: 80,    hint: 'http'    },
    { port: 443,   hint: 'https'   },
    { port: 22,    hint: 'ssh'     },
    { port: 23,    hint: 'telnet'  },
    { port: 62078, hint: 'ios'     },
    { port: 7000,  hint: 'airplay' },
    { port: 9100,  hint: 'printer' },
    { port: 515,   hint: 'printer' },
    { port: 631,   hint: 'printer' },
    { port: 3389,  hint: 'rdp'    },
    { port: 5900,  hint: 'vnc'    },
    { port: 8080,  hint: 'http'   },
    { port: 1883,  hint: 'mqtt'   },
    { port: 5683,  hint: 'coap'   },
];

function probePort(ip, port, timeoutMs = 600) {
    return new Promise((resolve) => {
        const sock = new net.Socket();
        sock.setTimeout(timeoutMs);
        sock.on('connect', () => { sock.destroy(); resolve(true);  });
        sock.on('error',   () => { sock.destroy(); resolve(false); });
        sock.on('timeout', () => { sock.destroy(); resolve(false); });
        sock.connect(port, ip);
    });
}

async function getOpenHints(ip) {
    const results = await Promise.all(
        PORT_HINTS.map(async ({ port, hint }) =>
            (await probePort(ip, port)) ? hint : null
        )
    );
    return results.filter(Boolean);
}

const OUI_MAP = {
    'ac:bc:32': 'Apple',        'a4:c3:f0': 'Apple',       'b4:e6:2d': 'Apple',
    '3c:22:fb': 'Apple',        '28:cf:e9': 'Apple',       '00:1e:c2': 'Apple',
    'f8:ff:c2': 'Apple',        'fc:3f:db': 'Apple',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
    '00:50:56': 'VMware',       '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',   '00:1c:42': 'Parallels',
    '00:1b:21': 'Intel',        '8c:8d:28': 'Intel',       'f4:02:70': 'Intel',
    'e4:5f:01': 'Samsung',      '04:d6:aa': 'Samsung',
    'fc:ec:da': 'Ubiquiti',
    '00:1a:2b': 'Cisco',
    '00:17:88': 'Philips Hue',
    '94:65:2d': 'HP',           '00:25:b3': 'HP',
    '00:24:d6': 'Nintendo',
    '98:b6:e9': 'Amazon',       'fc:65:de': 'Amazon',      '74:75:48': 'Amazon',
    '00:fc:8b': 'Google',       '54:60:09': 'Google',      'f4:f5:d8': 'Google',
    'a4:77:33': 'Google',
    '40:4e:36': 'Xiaomi',       'f8:a2:d6': 'Xiaomi',
    '00:50:f2': 'Microsoft',    '28:18:78': 'Microsoft',
};

function getVendor(mac) {
    return OUI_MAP[mac.substring(0, 8).toLowerCase()] || 'Unknown';
}

function classifyDevice({ vendor, openHints, isSelf, hostname }) {
    const v = vendor.toLowerCase();
    const h = (hostname || '').toLowerCase();
    const hints = openHints || [];

    if (isSelf) return 'PC/Laptop';
    if (['vmware', 'virtualbox', 'parallels'].some(k => v.includes(k))) return 'Virtual Machine';
    if (hints.includes('printer') || h.includes('print')) return 'Printer';
    if (v.includes('cisco') || v.includes('ubiquiti') || v.includes('netgear') ||
        v.includes('tp-link') || v.includes('asus') || v.includes('d-link') ||
        h.includes('router') || h.includes('gateway') || h.includes('fritzbox')) return 'Router';
    if (v.includes('apple')) {
        if (hints.includes('ios'))     return 'iPhone/iPad';
        if (hints.includes('airplay')) return 'Apple TV';
        if (hints.includes('ssh'))     return 'Mac';
        return 'Apple Device';
    }
    if (v.includes('amazon'))    return 'Amazon Device';
    if (v.includes('google'))    return 'Google Device';
    if (v.includes('raspberry')) return 'Raspberry Pi';
    if (v.includes('samsung')) {
        if (h.includes('tv') || hints.includes('airplay')) return 'Smart TV';
        return 'Android Phone';
    }
    if (v.includes('xiaomi'))    return 'Android Phone';
    if (v.includes('nintendo'))  return 'Gaming Console';
    if (v.includes('philips'))   return 'Smart Light';
    if (hints.includes('mqtt') || hints.includes('coap')) return 'IoT Device';
    if (hints.includes('rdp') || hints.includes('vnc') || hints.includes('ssh')) {
        if (hints.includes('http') || hints.includes('https')) return 'Server';
        return 'PC/Laptop';
    }
    if (hints.includes('ios'))   return 'iPhone/iPad';
    if (hints.includes('http'))  return 'Server';
    return 'Unknown';
}

let scanState = { status: 'idle', devices: [], lastScan: null, ownIp: null };

async function enrichDevice(d, ownIp) {
    const [hostname, openHints] = await Promise.all([
        resolveHostname(d.ip),
        getOpenHints(d.ip),
    ]);
    const vendor     = getVendor(d.mac);
    const isSelf     = d.ip === ownIp;
    const deviceType = classifyDevice({ vendor, mac: d.mac, openHints, isSelf, hostname });
    return { ...d, vendor, hostname, openHints, deviceType, self: isSelf };
}

async function runScan() {
    if (scanState.status === 'scanning') return;
    scanState.status  = 'scanning';
    scanState.devices = [];

    const netInfo = getLocalSubnet();
    if (!netInfo) { scanState.status = 'done'; return; }
    scanState.ownIp = netInfo.ownIp;

    await pingSubnet(netInfo.subnet);
    const arpDevices = await getArpTable();

    const selfRaw = { ip: netInfo.ownIp, mac: netInfo.mac };
    const allRaw  = [selfRaw, ...arpDevices.filter(d => d.ip !== netInfo.ownIp)];

    const enriched = await Promise.all(allRaw.map(d => enrichDevice(d, netInfo.ownIp)));

    scanState.devices = enriched.sort((a, b) =>
        parseInt(a.ip.split('.').pop()) - parseInt(b.ip.split('.').pop())
    );
    scanState.status   = 'done';
    scanState.lastScan = new Date().toLocaleTimeString('en-US');
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');

    if (req.url === '/scan') {
        runScan();
        res.end(JSON.stringify({ started: true }));
    } else if (req.url === '/status') {
        res.end(JSON.stringify(scanState));
    } else if (req.url && req.url.startsWith('/ping')) {
        const url   = new URL(req.url, 'http://localhost');
        const ip    = url.searchParams.get('ip');
        const isWin = process.platform === 'win32';
        const cmd   = isWin ? `ping -n 1 -w 500 ${ip}` : `ping -c 1 -W 1 ${ip}`;
        exec(cmd, (err) => {
            res.end(JSON.stringify({ reachable: !err }));
        });
    } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Not Found' }));
    }
});

server.listen(3000, () => console.log('NetScanner running on http://localhost:3000'));
