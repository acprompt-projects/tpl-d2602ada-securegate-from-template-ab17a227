const HIERARCHY = ['viewer', 'editor', 'admin'];

const ROLE_PERMISSIONS = {
  viewer:  ['metrics:read', 'status:read', 'incidents:read'],
  editor:  ['metrics:read', 'metrics:write', 'status:read', 'status:write', 'incidents:read', 'incidents:write'],
  admin:   ['metrics:read', 'metrics:write', 'metrics:delete', 'status:read', 'status:write', 'status:delete',
            'incidents:read', 'incidents:write', 'incidents:delete', 'users:read', 'users:write', 'users:delete', 'admin:all'],
};

function resolvePermissions(role) {
  const idx = HIERARCHY.indexOf(role);
  if (idx === -1) throw new Error(`Unknown role: ${role}`);
  const inherited = new Set();
  for (let i = idx; i >= 0; i--) {
    for (const perm of ROLE_PERMISSIONS[HIERARCHY[i]]) inherited.add(perm);
  }
  return Array.from(inherited);
}

function createPolicy(evaluator) {
  if (typeof evaluator !== 'function') throw new Error('Policy evaluator must be a function');
  return { evaluate: evaluator };
}

function hasPermission(userPerms, required) {
  if (userPerms.includes('admin:all')) return true;
  return required.every(p => userPerms.includes(p));
}

function rbacMiddleware({ permissions = [], policy = null, resourceOwnerCheck = null } = {}) {
  if (!Array.isArray(permissions)) throw new Error('permissions must be an array');
  return function (req, res, next) {
    const user = req.user;
    if (!user || !user.role) {
      return res.status(401).json({ error: 'Unauthorized: no user on request' });
    }
    let userPerms;
    try {
      userPerms = user.permissions || resolvePermissions(user.role);
    } catch (e) {
      return res.status(403).json({ error: e.message });
    }
    if (permissions.length > 0 && !hasPermission(userPerms, permissions)) {
      return res.status(403).json({ error: 'Forbidden: insufficient permissions', required: permissions });
    }
    if (policy && !policy.evaluate(req, user, userPerms)) {
      return res.status(403).json({ error: 'Forbidden: policy denied' });
    }
    if (resourceOwnerCheck && !resourceOwnerCheck(req, user)) {
      return res.status(403).json({ error: 'Forbidden: not resource owner' });
    }
    next();
  };
}

module.exports = { HIERARCHY, ROLE_PERMISSIONS, resolvePermissions, createPolicy, hasPermission, rbacMiddleware };