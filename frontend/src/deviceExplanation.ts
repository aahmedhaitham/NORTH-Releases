export function explainAddress(value: string) {
  const address = value.trim().toLowerCase().split('%')[0];
  if (address.includes(':')) {
    let canonical: string;
    try {
      canonical = new URL('http://[' + address + ']').hostname.slice(1, -1);
    } catch {
      return 'This value is not a recognized IP address.';
    }
    if (canonical === '::1') return 'IPv6 loopback. This address refers to the device itself.';
    const prefix = Number.parseInt(canonical.split(':')[0], 16);
    if ((prefix & 0xffc0) === 0xfe80) return 'Link-local IPv6. It is used on this network link and does not identify a device model.';
    if ((prefix & 0xfe00) === 0xfc00) return 'Unique-local IPv6. It is intended for private network use.';
    if (canonical.startsWith('2001:db8:') ||
        (prefix === 0x3fff && (Number.parseInt(canonical.split(':')[1], 16) & 0xf000) === 0)) {
      return 'Documentation IPv6. This range is reserved for examples.';
    }
    return 'IPv6 address. The address alone does not establish who owns it or where the device is.';
  }
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return 'This value is not a recognized IP address.';
  }
  const [a, b, c] = parts.map(Number);
  if (a === 127) return 'IPv4 loopback. This address refers to the device itself.';
  if (a === 169 && b === 254) return 'Link-local IPv4. It is used on this network link.';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return 'Private IPv4. Many networks can use this address. A router client name or endpoint record can help identify the device.';
  }
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
    return 'Documentation IPv4. This range is reserved for examples.';
  }
  return 'IPv4 address. The address alone does not establish who owns it or where the device is.';
}
