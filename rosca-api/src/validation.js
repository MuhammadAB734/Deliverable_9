function isNonEmptyString(value, min = 1, max = 255) {
  return typeof value === 'string' && value.trim().length >= min && value.trim().length <= max;
}

function isPositiveNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

function isPositiveInt(value) {
  return Number.isInteger(value) && value > 0;
}


function validateId(id) {
  const n = Number(id);
  return isPositiveInt(n) ? n : null;
}

function validateMember(body) {
  const errors = [];
  if (!isNonEmptyString(body.full_name, 2, 120)) errors.push('full_name must be 2-120 characters.');
  if (body.phone !== undefined && body.phone !== null && !isNonEmptyString(String(body.phone), 3, 30)) {
    errors.push('phone must be 3-30 characters when provided.');
  }
  if (body.email !== undefined && body.email !== null && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(body.email))) {
    errors.push('email must be a valid email address.');
  }
  if (body.status !== undefined && !['active', 'inactive'].includes(body.status)) errors.push('status must be active or inactive.');
  return errors;
}

function validateCircle(body) {
  const errors = [];
  if (!isNonEmptyString(body.name, 2, 120)) errors.push('name must be 2-120 characters.');
  if (!isPositiveNumber(body.contribution_amount)) errors.push('contribution_amount must be a positive number.');
  if (body.email !== undefined && body.email !== null && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(body.email))) {
    errors.push('email must be a valid email address.');
  }
  if (body.status !== undefined && !['active', 'inactive'].includes(body.status)) errors.push('status must be active or inactive.');
  return errors;
}

function validateMembership(body) {
  const errors = [];
  if (!isPositiveInt(body.member_id)) errors.push('member_id must be a positive integer.');
  if (!isPositiveInt(body.circle_id)) errors.push('circle_id must be a positive integer.');
  if (!isPositiveInt(body.rotation_position)) errors.push('rotation_position must be a positive integer.');
  if (body.status !== undefined && !['active', 'inactive'].includes(body.status)) errors.push('status must be active or inactive.');
  return errors;
}

function validateCycle(body) {
  const errors = [];
  if (!isPositiveInt(body.circle_id)) errors.push('circle_id must be a positive integer.');
  if (!isPositiveInt(body.cycle_number)) errors.push('cycle_number must be a positive integer.');
  if (body.status !== undefined && !['scheduled', 'open', 'closed', 'paid'].includes(body.status)) {
    errors.push('status must be scheduled, open, closed, or paid.');
  }
  return errors;
}

function validateContribution(body) {
  const errors = [];
  if (!isPositiveNumber(body.amount)) errors.push('amount must be a positive number.');
  if (!isPositiveInt(body.membership_id)) errors.push('membership_id must be a positive integer.');
  if (!isPositiveInt(body.cycle_id)) errors.push('cycle_id must be a positive integer.');
  if (body.payment_status !== undefined && !['pending', 'paid', 'failed', 'waived'].includes(body.payment_status)) {
    errors.push('payment_status must be pending, paid, failed, or waived.');
  }
  return errors;
}


// function validateContribution(content) {
//   const errors = [];
//   if (!isPositiveNumber(content.amount)) errors.push('amount must be a positive number.');
//   if (!isPositiveInt(content.cycle_id)) errors.push('cycle_id must be a positive integer.');
//   if (content.payment_status !== undefined && !['pending', 'paid', 'failed', 'waived'].includes(body.payment_status)) {
//     errors.push('payment_status must be pending, paid, failed, or waived.');
//   }
//   return errors;
// }


function validatePayout(body) {
  const errors = [];
  if (!isPositiveNumber(body.amount)) errors.push('amount must be a positive number.');
  if (!isPositiveInt(body.cycle_id)) errors.push('cycle_id must be a positive integer.');
  if (!isPositiveInt(body.membership_id)) errors.push('membership_id must be a positive integer.');
  if (body.status !== undefined && !['pending', 'paid', 'failed'].includes(body.status)) {
    errors.push('status must be pending, paid, or failed.');
  }
  return errors;
}

module.exports = {
  validateId,
  validateMember,
  validateCircle,
  validateMembership,
  validateCycle,
  validateContribution,
  validatePayout
};
