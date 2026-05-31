module.exports = function notFound(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.statusCode = 404;
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  res.end(JSON.stringify({ error: 'Not found' }));
};
