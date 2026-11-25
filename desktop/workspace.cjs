function workspaceOrigin(value) {
  if (typeof value !== 'string') throw new Error('Enter your NORTH Cloud address.');
  const url = new URL(value.trim());
  if (url.protocol !== 'https:' || !url.hostname.includes('.') || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Enter the HTTPS workspace address without a page path, password, or query.');
  }
  return url.origin;
}

module.exports = { workspaceOrigin };
