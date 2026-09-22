/* NetDeck manufacturer lookup: the leading bytes of a MAC address identify who made the network chip.
   Two layers: a small curated table of friendly names (VMs, containers, single-board computers) that is
   always available, and the full IEEE registry (oui-data.json, ~54,000 prefixes in 24/28/36-bit blocks,
   built by tools/build-oui.js) fetched in the background at startup. Locally-administered addresses are
   detected exactly: phones, tablets and laptops use random "private" MAC addresses on Wi-Fi, which belong
   to no vendor. */
window.NetDeckOui = (() => {
  const TABLE = {
    // virtual machines and containers
    '00155D': 'Microsoft Hyper-V', '005056': 'VMware', '000C29': 'VMware', '000569': 'VMware', '001C14': 'VMware',
    '080027': 'VirtualBox', '001C42': 'Parallels', '525400': 'QEMU / KVM', '00163E': 'Xen',
    // single-board computers and IoT chips
    'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi', 'D83ADD': 'Raspberry Pi', '2CCF67': 'Raspberry Pi', '28CDC1': 'Raspberry Pi',
    '240AC4': 'Espressif (IoT)', '30AEA4': 'Espressif (IoT)', 'A4CF12': 'Espressif (IoT)', 'CC50E3': 'Espressif (IoT)', '84F3EB': 'Espressif (IoT)',
    '5CCF7F': 'Espressif (IoT)', 'ECFABC': 'Espressif (IoT)', '2CF432': 'Espressif (IoT)', 'AC67B2': 'Espressif (IoT)', '3C71BF': 'Espressif (IoT)',
    '807D3A': 'Espressif (IoT)', 'B4E62D': 'Espressif (IoT)', 'BCDDC2': 'Espressif (IoT)', '84CCA8': 'Espressif (IoT)', '8CAAB5': 'Espressif (IoT)',
    'A020A6': 'Espressif (IoT)', '600194': 'Espressif (IoT)', '18FE34': 'Espressif (IoT)', '68C63A': 'Espressif (IoT)', 'DC4F22': 'Espressif (IoT)',
    'C44F33': 'Espressif (IoT)', '246F28': 'Espressif (IoT)', '4C11AE': 'Espressif (IoT)', '7C9EBD': 'Espressif (IoT)',
    // Apple
    '000393': 'Apple', '000A27': 'Apple', '000A95': 'Apple', '000D93': 'Apple', '001124': 'Apple', '001451': 'Apple', '0016CB': 'Apple',
    '0017F2': 'Apple', '0019E3': 'Apple', '001B63': 'Apple', '001CB3': 'Apple', '001EC2': 'Apple', '001F5B': 'Apple', '001FF3': 'Apple',
    '0021E9': 'Apple', '002312': 'Apple', '002500': 'Apple', '0026BB': 'Apple', '3C0754': 'Apple', '28CFE9': 'Apple', 'A45E60': 'Apple',
    'ACBC32': 'Apple', 'F01898': 'Apple', '8C8590': 'Apple', 'D0817A': 'Apple',
    // Google / Nest, Amazon
    '3C5AB4': 'Google', 'F4F5D8': 'Google', 'F4F5E8': 'Google', '001A11': 'Google', '18B430': 'Google Nest',
    '44650D': 'Amazon', 'FCA183': 'Amazon', 'F0272D': 'Amazon', '74C246': 'Amazon', '0C47C9': 'Amazon', '34D270': 'Amazon', '50DCE7': 'Amazon',
    '84D6D0': 'Amazon', 'A002DC': 'Amazon', 'AC63BE': 'Amazon', 'B47C9C': 'Amazon', 'FC65DE': 'Amazon', '40B4CD': 'Amazon', '6837E9': 'Amazon',
    '78E103': 'Amazon', '6854FD': 'Amazon', '8871E5': 'Amazon',
    // routers, mesh and networking gear
    'F8BBBF': 'eero', '50C7BF': 'TP-Link', 'B0BE76': 'TP-Link', 'EC086B': 'TP-Link', '14CC20': 'TP-Link', '18A6F7': 'TP-Link', '1C3BF3': 'TP-Link',
    '30B5C2': 'TP-Link', '60E327': 'TP-Link', '98DAC4': 'TP-Link', 'AC84C6': 'TP-Link', 'C025E9': 'TP-Link', 'D80D17': 'TP-Link', 'F4F26D': 'TP-Link',
    '54C80F': 'TP-Link', 'B04E26': 'TP-Link',
    '002722': 'Ubiquiti', '0418D6': 'Ubiquiti', '24A43C': 'Ubiquiti', '44D9E7': 'Ubiquiti', '687251': 'Ubiquiti', '788A20': 'Ubiquiti', '802AA8': 'Ubiquiti',
    'B4FBE4': 'Ubiquiti', 'DC9FDB': 'Ubiquiti', 'F09FC2': 'Ubiquiti', 'FCECDA': 'Ubiquiti', '18E829': 'Ubiquiti', '74ACB9': 'Ubiquiti', 'E063DA': 'Ubiquiti',
    '00146C': 'Netgear', '001B2F': 'Netgear', '001E2A': 'Netgear', '00223F': 'Netgear', '0024B2': 'Netgear', '204E7F': 'Netgear', '28C68E': 'Netgear',
    '2CB05D': 'Netgear', '30469A': 'Netgear', '4494FC': 'Netgear', '9C3DCF': 'Netgear', 'A021B7': 'Netgear', 'C03F0E': 'Netgear', 'E091F5': 'Netgear',
    '000C41': 'Linksys', '001217': 'Linksys', '001310': 'Linksys', '0014BF': 'Linksys', '0016B6': 'Linksys', '001839': 'Linksys', '001A70': 'Linksys',
    '001C10': 'Linksys', '001D7E': 'Linksys', '002129': 'Linksys', '00226B': 'Linksys', '002369': 'Linksys', '00259C': 'Linksys',
    '00055D': 'D-Link', '000D88': 'D-Link', '001195': 'D-Link', '001346': 'D-Link', '0015E9': 'D-Link', '00179A': 'D-Link', '001B11': 'D-Link',
    '001CF0': 'D-Link', '001E58': 'D-Link', '002191': 'D-Link', '0022B0': 'D-Link', '002401': 'D-Link', '00265A': 'D-Link',
    '00000C': 'Cisco', '00180A': 'Cisco Meraki', '0C8DDB': 'Cisco Meraki', '88155F': 'Cisco Meraki', 'E0553D': 'Cisco Meraki', 'E0CBBC': 'Cisco Meraki',
    '000B86': 'Aruba', '001A1E': 'Aruba', '24DEC6': 'Aruba', '6CF37F': 'Aruba', '9C1C12': 'Aruba', 'D8C7C8': 'Aruba',
    '00090F': 'Fortinet', '085B0E': 'Fortinet', '906CAC': 'Fortinet',
    '000C42': 'MikroTik', '4C5E0C': 'MikroTik', '6C3B6B': 'MikroTik', 'CC2DE0': 'MikroTik', 'D4CA6D': 'MikroTik', 'E48D8C': 'MikroTik',
    // computers and network cards
    '00E04C': 'Realtek', '001B21': 'Intel', '0013CE': 'Intel', '001500': 'Intel', '00166F': 'Intel', '0019D1': 'Intel', '001CBF': 'Intel',
    '001E64': 'Intel', '001F3B': 'Intel', '00216A': 'Intel', '002314': 'Intel', '0024D7': 'Intel',
    '00065B': 'Dell', '000874': 'Dell', '000BDB': 'Dell', '000D56': 'Dell', '000F1F': 'Dell', '001143': 'Dell', '00123F': 'Dell', '001372': 'Dell',
    '001422': 'Dell', '0015C5': 'Dell', '00188B': 'Dell', '0019B9': 'Dell', '001AA0': 'Dell', '001C23': 'Dell', '001D09': 'Dell', '001E4F': 'Dell',
    '002170': 'Dell', '00219B': 'Dell', '002219': 'Dell', '0024E8': 'Dell', '0026B9': 'Dell', 'B8AC6F': 'Dell', 'D4BED9': 'Dell', 'F8BC12': 'Dell', '18A99B': 'Dell',
    '001083': 'HP', '0017A4': 'HP', '001A4B': 'HP', '001B78': 'HP', '001CC4': 'HP', '002264': 'HP', '3CD92B': 'HP', '9C8E99': 'HP', 'B499BA': 'HP',
    '0003FF': 'Microsoft', '000D3A': 'Microsoft', '00125A': 'Microsoft', '001DD8': 'Microsoft', '002248': 'Microsoft', '0025AE': 'Microsoft',
    '0050F2': 'Microsoft', '7C1E52': 'Microsoft', '7CED8D': 'Microsoft', '985FD3': 'Microsoft', 'C83F26': 'Microsoft',
    // printers, storage, cameras
    '000048': 'Epson', '0026AB': 'Epson', '64EB8C': 'Epson', 'A4EE57': 'Epson', 'AC1826': 'Epson', 'E0BB9E': 'Epson',
    '008077': 'Brother', '001BA9': 'Brother', '30055C': 'Brother', '000085': 'Canon',
    '001132': 'Synology', '00089B': 'QNAP', '245EBE': 'QNAP',
    '00408C': 'Axis', 'ACCC8E': 'Axis', 'B8A44F': 'Axis', '4419B6': 'Hikvision', '4CBD8F': 'Hikvision', 'BCAD28': 'Hikvision', 'C056E3': 'Hikvision', 'C42F90': 'Hikvision',
    '3CEF8C': 'Dahua', '4C11BF': 'Dahua', '9002A9': 'Dahua', 'E0508B': 'Dahua',
    '2CAA8E': 'Wyze', '7C78B2': 'Wyze', 'D03F27': 'Wyze',
    // TVs, speakers, consoles, smart home
    '000E58': 'Sonos', '5CAAFD': 'Sonos', 'B8E937': 'Sonos', '949F3E': 'Sonos', '7828CA': 'Sonos', '347E5C': 'Sonos', '48A6B8': 'Sonos',
    '001788': 'Philips Hue', 'ECB5FA': 'Philips Hue', 'D073D5': 'LIFX',
    '001150': 'Belkin', '001CDF': 'Belkin', '08863B': 'Belkin', '944452': 'Belkin', 'B4750E': 'Belkin', 'C05627': 'Belkin', 'EC1A59': 'Belkin',
    '000D4B': 'Roku', 'B0A737': 'Roku', 'B83E59': 'Roku', 'CC6DA0': 'Roku', 'D83134': 'Roku', 'DC3A5E': 'Roku', 'AC3A7A': 'Roku', '8C4962': 'Roku',
    '0009BF': 'Nintendo', '001656': 'Nintendo', '0017AB': 'Nintendo', '00191D': 'Nintendo', '0019FD': 'Nintendo', '001AE9': 'Nintendo', '001B7A': 'Nintendo',
    '001BEA': 'Nintendo', '001CBE': 'Nintendo', '001DBC': 'Nintendo', '001E35': 'Nintendo', '001F32': 'Nintendo', '001FC5': 'Nintendo', '002147': 'Nintendo',
    '0021BD': 'Nintendo', '00224C': 'Nintendo', '0022AA': 'Nintendo', '0022D7': 'Nintendo', '002331': 'Nintendo', '0023CC': 'Nintendo', '00241E': 'Nintendo',
    '002444': 'Nintendo', '0024F3': 'Nintendo', '0025A0': 'Nintendo', '002659': 'Nintendo', '002709': 'Nintendo',
    '00041F': 'Sony PlayStation', '001315': 'Sony PlayStation', '0015C1': 'Sony PlayStation', '0019C5': 'Sony PlayStation', '001D0D': 'Sony PlayStation',
    '001FA7': 'Sony PlayStation', '00248D': 'Sony PlayStation', '280DFC': 'Sony PlayStation', '709E29': 'Sony PlayStation', 'F8D0AC': 'Sony PlayStation',
    '0012FB': 'Samsung', '001599': 'Samsung', '001632': 'Samsung', '0017C9': 'Samsung', '0018AF': 'Samsung', '001A8A': 'Samsung', '001D25': 'Samsung',
    '002339': 'Samsung', '5001BB': 'Samsung',
    '001C62': 'LG', '001E75': 'LG', '001F6B': 'LG', '001FE3': 'LG', '0021FB': 'LG', '0022A9': 'LG', '002483': 'LG', '0025E5': 'LG', '0026E2': 'LG',
    '10F96F': 'LG', '2021A5': 'LG', 'A816B2': 'LG', 'CC2D8C': 'LG',
    '286C07': 'Xiaomi', '34CE00': 'Xiaomi', '640980': 'Xiaomi', '7811DC': 'Xiaomi', '8CBEBE': 'Xiaomi', '98FAE3': 'Xiaomi', 'F48B32': 'Xiaomi', 'F8A45F': 'Xiaomi',
    '001E10': 'Huawei', '00259E': 'Huawei', '002568': 'Huawei', '286ED4': 'Huawei', '4C5499': 'Huawei', '781DBA': 'Huawei', 'ACE215': 'Huawei',
  };

  const hex = (mac) => String(mac || '').replace(/[^0-9a-f]/gi, '').toUpperCase();

  /* The second hex digit carries the "locally administered" bit: 2, 6, A or E means the address was
     made up by software rather than assigned to a manufacturer. */
  function isLocallyAdministered(mac) {
    const h = hex(mac);
    return h.length >= 2 && '26AE'.includes(h[1]);
  }

  // The registry: prefix (6, 7 or 9 hex characters) → manufacturer. Empty until oui-data.json has loaded.
  const REGISTRY = new Map();
  let registryError = '';
  const ready = (typeof fetch === 'function' ? fetch('oui-data.json', { cache: 'force-cache' }).then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }) : Promise.reject(new Error('no fetch')))
    .then((data) => { for (const [name, prefixes] of Object.entries(data)) for (const p of prefixes) REGISTRY.set(p, name); return REGISTRY.size; })
    .catch((e) => { registryError = String(e && e.message || e); return 0; });

  function lookup(mac) {
    const h = hex(mac);
    if (h.length < 6) return '';
    if (h.startsWith('0242')) return 'Docker container';
    if (isLocallyAdministered(h)) return 'private address (randomised)';
    // curated names first (they are friendlier: "Microsoft Hyper-V", not "Microsoft"), then the longest registry block that matches
    return TABLE[h.slice(0, 6)] || REGISTRY.get(h.slice(0, 9)) || REGISTRY.get(h.slice(0, 7)) || REGISTRY.get(h.slice(0, 6)) || '';
  }

  return { lookup, isLocallyAdministered, ready, get size() { return REGISTRY.size; }, get curated() { return Object.keys(TABLE).length; }, get error() { return registryError; } };
})();
