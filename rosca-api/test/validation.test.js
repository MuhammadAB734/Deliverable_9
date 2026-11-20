const test = require('node:test');
const assert = require('node:assert/strict');
const { validateMember, validateCircle, validateMembership, validateContribution } = require('../src/validation');

test('member validation rejects missing name', () => {
  assert.ok(validateMember({}).length > 0);
});

test('circle validation rejects non-positive contribution', () => {
  assert.ok(validateCircle({name:'Test', contribution_amount:0}).length > 0);
});

test('membership validation requires positive integer references', () => {
  assert.ok(validateMembership({member_id:0, circle_id:1, rotation_position:1}).length > 0);
});

test('contribution validation requires positive amount', () => {
  assert.ok(validateContribution({amount:-1, membership_id:1, cycle_id:1}).length > 0);
});
