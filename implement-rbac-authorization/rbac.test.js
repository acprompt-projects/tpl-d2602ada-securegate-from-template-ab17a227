const assert = require('assert');
const { HIERARCHY, ROLE_PERMISSIONS, resolvePermissions, createPolicy, hasPermission, rbacMiddleware } = require('./rbac');

(() => {
  // Test resolvePermissions - viewer gets only viewer perms
  const vp = resolvePermissions('viewer');
  assert.deepStrictEqual(vp.sort(), ROLE_PERMISSIONS.viewer.sort());

  // Test resolvePermissions - editor inherits viewer + editor
  const ep = resolvePermissions('editor');
  assert.ok(ep.includes('metrics:read'), 'editor inherits viewer read');
  assert.ok(ep.includes('metrics:write'), 'editor has own write');

  // Test resolvePermissions - admin inherits all
  const ap = resolvePermissions('admin');
  assert.ok(ap.includes('admin:all'));
  assert.ok(ap.includes('metrics:read'));

  // Test unknown role throws
  assert.throws(() => resolvePermissions('guest'), /Unknown role/);

  // Test hasPermission
  assert.ok(hasPermission(['admin:all'], ['anything']));
  assert.ok(hasPermission(['metrics:read', 'metrics:write'], ['metrics:read']));
  assert.ok(!hasPermission(['metrics:read'], ['metrics:write']));
  assert.ok(hasPermission(['a', 'b'], ['a', 'b']));
  assert.ok(!hasPermission(['a'], ['a', 'b']));

  // Test createPolicy
  const policy = createPolicy((req, user) => user.org === req.params.org);
  assert.strictEqual(typeof policy.evaluate, 'function');
  assert.throws(() => createPolicy('bad'), /Policy evaluator must be a function/);

  // Test middleware - no user
  const res1 = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; } };
  let called1 = false;
  rbacMiddleware({ permissions: ['metrics:read'] })({}, res1, () => { called1 = true; });
  assert.strictEqual(res1.statusCode, 401);
  assert.ok(!called1);

  // Test middleware - viewer allowed read
  const res2 = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; } };
  let called2 = false;
  rbacMiddleware({ permissions: ['metrics:read'] })({ user: { role: 'viewer' } }, res2, () => { called2 = true; });
  assert.strictEqual(res2.statusCode, 0);
  assert.ok(called2);

  // Test middleware - viewer denied write
  const res3 = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; } };
  let called3 = false;
  rbacMiddleware({ permissions: ['metrics:write'] })({ user: { role: 'viewer' } }, res3, () => { called3 = true; });
  assert.strictEqual(res3.statusCode, 403);
  assert.ok(!called3);

  // Test middleware - policy deny
  const res4 = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; } };
  const denyPolicy = createPolicy(() => false);
  let called4 = false;
  rbacMiddleware({ policy: denyPolicy })({ user: { role: 'admin' } }, res4, () => { called4 = true; });
  assert.strictEqual(res4.statusCode, 403);

  // Test middleware - resourceOwnerCheck
  const res5 = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; } };
  let called5 = false;
  const ownerCheck = (req, user) => user.id === req.resourceOwnerId;
  rbacMiddleware({ resourceOwnerCheck: ownerCheck })({ user: { role: 'viewer', id: 'u1' }, resourceOwnerId: 'u2' }, res5, () => { called5 = true; });
  assert.strictEqual(res5.statusCode, 403);

  // Test middleware - custom permissions on user object
  const res6 = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; } };
  let called6 = false;
  rbacMiddleware({ permissions: ['custom:perm'] })({ user: { role: 'viewer', permissions: ['custom:perm'] } }, res6, () => { called6 = true; });
  assert.strictEqual(res6.statusCode, 0);
  assert.ok(called6);

  console.log('All RBAC tests passed ✓');
})();