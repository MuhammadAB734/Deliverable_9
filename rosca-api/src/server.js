const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const crypto = require("node:crypto");
const { promisify } = require("node:util");
const scrypt = promisify(crypto.scrypt);
const pool = require("./db");
const {
  validateId,
  validateMember,
  validateCircle,
  validateMembership,
  validateCycle,
  validateContribution,
  validatePayout,
} = require("./validation");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");
app.use(helmet());
app.use(
  cors({
    origin: (process.env.CORS_ORIGIN)
      .split(",")
      .map((x) => x.trim()),
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  }),
);
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  req.cookies = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0)
      req.cookies[part.slice(0, i).trim()] = decodeURIComponent(
        part.slice(i + 1).trim(),
      );
  }
  next();
});
app.use(morgan("combined"));

app.use(
  "/api/",
  rateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
    max: Number(process.env.RATE_LIMIT_MAX || 100),
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many requests. Please try again later." },
  }),
);

function sendValidation(res, errors) {
  return res.status(400).json({ error: "Validation failed", details: errors });
}

function handleDbError(res, err) {
  if (err && err.code === "ER_DUP_ENTRY") {
    return res.status(409).json({
      error: "Conflict",
      message: "The requested record violates a uniqueness rule.",
    });
  }

  if (err && err.code === "ER_NO_REFERENCED_ROW_2") {
    return res.status(400).json({
      error: "Invalid reference",
      message: "A referenced record does not exist.",
    });
  }

  if (
    err &&
    (err.code === "ER_ROW_IS_REFERENCED_2" ||
      err.code === "ER_ROW_IS_REFERENCED")
  ) {
    return res.status(409).json({
      error: "Conflict",
      message: "The record is referenced by another record.",
    });
  }

  if (
    err &&
    (err.code === "ER_CHECK_CONSTRAINT_VIOLATED" ||
      err.code === "ER_WRONG_VALUE_FOR_FIELD")
  ) {
    return res.status(400).json({
      error: "Constraint violation",
      message: "One or more values failed a database constraint.",
    });
  }

  console.error(err);
  return res.status(500).json({ error: "Internal server error" });
}

async function one(sql, params = []) {
  const [rows] = await pool.execute(sql, params);

  return rows[0];
}

async function all(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "rosca-api", database: "mysql" });
});

app.get("/api/docs", (req, res) => {
  res.json({
    name: "ROSCA REST API",
    track: "A",
    database: "MySQL",
    security: [
      "helmet",
      "CORS allow-list",
      "rate limiting",
      "JSON body size limit", //
      "parameterized SQL",
      "input validation",
    ],
    resources: [
      "members",
      "circles",
      "memberships",
      "cycles",
      "contributions",
      "payouts",
    ],
    special_operation: "POST /api/circles/:id/generate-schedule",
  });
});
const SESSION_COOKIE = "rosca_session";
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 1);
const COOKIE_SECURE = process.env.NODE_ENV === "production";

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString("hex")}$${Buffer.from(key).toString("hex")}`;
}
async function verifyPassword(password, encoded) {
  const parts = String(encoded || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  try {
    const expected = Buffer.from(parts[2], "hex");
    const actual = Buffer.from(
      await scrypt(password, Buffer.from(parts[1], "hex"), expected.length),
    );
    return (
      expected.length === actual.length &&
      crypto.timingSafeEqual(expected, actual)
    );
  } catch {
    return false;
  }
}
const tokenHash = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");
function setCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "strict",
    path: "/api",
    maxAge: SESSION_DAYS * 86400000,
  });
}
function clearCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "strict",
    path: "/api",
  });
}
async function createSession(userId, res) {
  const token = crypto.randomBytes(32).toString("base64url");
  await pool.execute(
    "INSERT INTO app_sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
    [userId, tokenHash(token), new Date(Date.now() + SESSION_DAYS * 86400000)],
  );
  setCookie(res, token);
}
async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.[SESSION_COOKIE];
    if (!token || token.length > 200)
      return res.status(401).json({ error: "Authentication required" });
    const [rows] = await pool.execute(
      `
      SELECT u.user_id, u.username, u.role, u.member_id
      FROM app_sessions s JOIN app_users u ON u.user_id=s.user_id
      WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>CURRENT_TIMESTAMP
        AND u.account_status='ACTIVE' LIMIT 1`,
      [tokenHash(token)],
    );
    if (!rows.length)
      return res.status(401).json({ error: "Session expired or invalid" });
    req.user = rows[0];
    next();
  } catch (err) {
    handleDbError(res, err);
  }
}
function requireOrganizer(req, res, next) {
  if (req.user?.role !== "ORGANIZER")
    return res.status(403).json({ error: "Organizer permission required" });
  next();
}

app.post(
  "/api/auth/bootstrap",
  rateLimit({ windowMs: 900000, max: 5 }),
  async (req, res) => {
    try {
      const username = String(req.body?.username || "").trim(),
        password = req.body?.password;
      if (
        !/^[A-Za-z0-9_.-]{3,60}$/.test(username) ||
        typeof password !== "string" ||
        password.length < 12
      )
        return res
          .status(400)
          .json({
            error:
              "Username must be 3-60 safe characters and password at least 12 characters.",
          });
      const [existing] = await pool.execute(
        "SELECT user_id FROM app_users LIMIT 1",
      );
      if (existing.length)
        return res
          .status(409)
          .json({ error: "Initial organizer already exists." });
      const [result] = await pool.execute(
        "INSERT INTO app_users (username,password_hash,role) VALUES (?,?,'ORGANIZER')",
        [username, await hashPassword(password)],
      );
      await createSession(result.insertId, res);
      res
        .status(201)
        .json({ user: { username, role: "ORGANIZER", member_id: null } });
    } catch (err) {
      handleDbError(res, err);
    }
  },
);
app.post(
  "/api/auth/login",
  rateLimit({ windowMs: 900000, max: 10 }),
  async (req, res) => {
    try {
      const username = String(req.body?.username || "").trim(),
        password = req.body?.password;
      if (!username || typeof password !== "string")
        return res
          .status(400)
          .json({ error: "Username and password are required." });
      const [rows] = await pool.execute(
        "SELECT user_id,username,password_hash,role,member_id FROM app_users WHERE username=? AND account_status='ACTIVE' LIMIT 1",
        [username],
      );
      const u = rows[0];
      if (!u || !(await verifyPassword(password, u.password_hash)))
        return res.status(401).json({ error: "Invalid username or password." });
      await createSession(u.user_id, res);
      res.json({
        user: { username: u.username, role: u.role, member_id: u.member_id },
      });
    } catch (err) {
      handleDbError(res, err);
    }
  },
);
app.post("/api/auth/logout", async (req, res) => {
  try {
    const token = req.cookies?.[SESSION_COOKIE];
    if (token)
      await pool.execute(
        "UPDATE app_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=? AND revoked_at IS NULL",
        [tokenHash(token)],
      );
    clearCookie(res);
    res.status(204).send();
  } catch (err) {
    handleDbError(res, err);
  }
});
app.get("/api/auth/me", requireAuth, (req, res) =>
  res.json({ user: req.user }),
);
app.get("/api/me", requireAuth, async (req, res) => {
  if (req.user.role === "ORGANIZER")
    return res.json({
      user: req.user,
      member: null,
      memberships: [],
      contributions: [],
      payouts: [],
    });
  if (!req.user.member_id)
    return res
      .status(403)
      .json({ error: "Member account is not linked to a member record." });
  try {
    const member = await one(
      "SELECT member_id,full_name,phone,email,status FROM members WHERE member_id=?",
      [req.user.member_id],
    );
    const memberships = await all(
      "SELECT membership_id,circle_id,rotation_position,status FROM memberships WHERE member_id=?",
      [req.user.member_id],
    );
    const contributions = await all(
      `SELECT c.contribution_id,c.amount,c.contribution_date,c.payment_status,c.membership_id,c.cycle_id
      FROM contributions c JOIN memberships m ON m.membership_id=c.membership_id WHERE m.member_id=?`,
      [req.user.member_id],
    );
    const payouts = await all(
      `SELECT p.payout_id,p.amount,p.payout_date,p.status,p.cycle_id,p.membership_id
      FROM payouts p JOIN memberships m ON m.membership_id=p.membership_id WHERE m.member_id=?`,
      [req.user.member_id],
    );
    res.json({ user: req.user, member, memberships, contributions, payouts });
  } catch (err) {
    handleDbError(res, err);
  }
});


app.post("/api/auth/users", requireAuth, requireOrganizer, async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim(),
      password = req.body?.password;
    const role = req.body?.role,
      memberId = req.body?.member_id ?? null;
      // memberId = req.body?.member_id ;

    if (
      !/^[A-Za-z0-9_.-]{3,60}$/.test(username) ||
      typeof password !== "string" ||
      password.length < 12 ||
      !["ORGANIZER", "MEMBER"].includes(role) ||
      (role === "MEMBER" &&
        (!Number.isInteger(Number(memberId)) || Number(memberId) < 1)) ||
      (role === "ORGANIZER" && memberId !== null)
    )
      return res
        .status(400)
        .json({
          error:
            "Invalid account details. Use a 12+ character password; member accounts require member_id.",
        });
    const [result] = await pool.execute(
      "INSERT INTO app_users (username,password_hash,role,member_id) VALUES (?,?,?,?)",
      [
        username,
        await hashPassword(password),
        role,
        role === "MEMBER" ? Number(memberId) : null,
      ],
    );
    res
      .status(201)
      .json({
        user_id: result.insertId,
        username,
        role,
        member_id: role === "MEMBER" ? Number(memberId) : null,
      });
  } catch (err) {
    handleDbError(res, err);
  }
});



// func han

// Restrict cookie-authenticated writes to the configured frontend origin.
app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const origin = req.get("origin");
  const allowed = (process.env.CORS_ORIGIN)
    .split(",")
    .map((x) => x.trim());
  if (origin && !allowed.includes(origin))
    return res.status(403).json({ error: "Request origin not allowed" });
  next();
});
app.use("/api", requireAuth, requireOrganizer);

function crudRoutes({
  pathName,
  table,
  idColumn,
  validate,
  columns,
  beforeWrite,
}) {
  app.get(`/api/${pathName}`, async (req, res) => {
    try {
      res.json(
        await all(
          `SELECT ${columns.join(", ")} FROM ${table} ORDER BY ${idColumn} DESC`,
        ),
      );
    } catch (err) {
      handleDbError(res, err);
    }
  });

  app.get(`/api/${pathName}/:id`, async (req, res) => {
    const id = validateId(req.params.id);

    if (!id) {
      return res.status(400).json({ error: "Invalid id" });
    }

    try {
      const row = await one(
        `SELECT ${columns.join(", ")} FROM ${table} WHERE ${idColumn} = ?`,
        [id],
      );
      if (!row) return res.status(404).json({ error: "Not found" });
      res.json(row);
    } catch (err) {
      handleDbError(res, err);
    }
  });


// app.post(`/apis/${pathName}`, async (req, res) => {

  app.post(`/api/${pathName}`, async (req, res) => {
    const errors = validate(req.body || {});
    if (errors.length) return sendValidation(res, errors);

    try {
      if (beforeWrite) await beforeWrite(req.body);

      const writable = columns.filter(
        (c) =>
          !c.includes(" AS ") &&
          c !== idColumn &&
          !c.includes("created_at") &&
          !c.includes("updated_at"),
      );

      const fields = writable.filter((n) =>
        Object.prototype.hasOwnProperty.call(req.body, n),
      );
      if (!fields.length)
        return res.status(400).json({ error: "No writable fields supplied." });

      const placeholders = fields.map(() => "?").join(", ");
      const [result] = await pool.execute(
        `INSERT INTO ${table} (${fields.join(", ")}) VALUES (${placeholders})`,
        fields.map((f) => req.body[f]),
      );

      const row = await one(
        `SELECT ${columns.join(", ")} FROM ${table} WHERE ${idColumn} = ?`,
        [result.insertId],
      );

      res.status(201).json(row);
    } catch (err) {
      handleDbError(res, err);
    }
  });

  app.put(`/api/${pathName}/:id`, async (req, res) => {
    const id = validateId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid id" });

    const errors = validate(req.body || {});
    if (errors.length) return sendValidation(res, errors);

    const writable = columns.filter(
      (c) =>
        !c.includes(" AS ") &&
        c !== idColumn &&
        !c.includes("created_at") &&
        !c.includes("updated_at"),
    );

    // const fields = writable.filter(n => Object.prototype.hasOwnProperty.call(req.body, n));
    const fields = writable.filter((n) =>
      Object.prototype.hasOwnProperty.call(req.body, n),
    );

    if (!fields.length)
      return res.status(400).json({ error: "No updatable fields supplied." });

    try {
      const existing = await one(
        `SELECT ${idColumn} FROM ${table} WHERE ${idColumn} = ?`,
        [id],
      );
      if (!existing) return res.status(404).json({ error: "Not found" });

      if (beforeWrite) await beforeWrite(req.body, id);

      const sets = fields.map((f) => `${f} = ?`).join(", ");
      await pool.execute(`UPDATE ${table} SET ${sets} WHERE ${idColumn} = ?`, [
        ...fields.map((f) => req.body[f]),
        id,
      ]);

      res.json(
        await one(
          `SELECT ${columns.join(", ")} FROM ${table} WHERE ${idColumn} = ?`,
          [id],
        ),
      );
    } catch (err) {
      handleDbError(res, err);
    }
  });



  app.delete(`/api/${pathName}/:id`, async (req, res) => {
    const id = validateId(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid id" });

    try {
      const existing = await one(
        `SELECT ${idColumn} FROM ${table} WHERE ${idColumn} = ?`,
        [id],
      );
      if (!existing) return res.status(404).json({ error: "Not found" });

      await pool.execute(`DELETE FROM ${table} WHERE ${idColumn} = ?`, [id]);
      res.status(204).send();
    } catch (err) {
      handleDbError(res, err);
    }
  });
}

crudRoutes({
  pathName: "members",
  table: "members",
  idColumn: "member_id",
  validate: validateMember,
  columns: [
    "member_id",
    "full_name",
    "phone",
    "email",
    "status",
    "created_at",
    "updated_at",
  ],
});

crudRoutes({
  pathName: "circles",
  table: "circles",
  idColumn: "circle_id",
  validate: validateCircle,
  columns: [
    "circle_id",
    "name",
    "contribution_amount",
    "email",
    "status",
    "created_at",
    "updated_at",
  ],
});

// crudRoutes({
//   pathName: "cycles",
//   table: "cycles",
//   idColumn: "cycle_id",
//   validate: validateCycle,
//   columns: [
//     "cycle_id",
//     "circle_id",
//     "cycle_number",
//     "status",
//     "starts_on",
//     "ends_on",
//     "created_at",
//     "updated_at",
//   ],
// });

crudRoutes({
  pathName: "memberships",
  table: "memberships",
  idColumn: "membership_id",
  validate: validateMembership,
  columns: [
    "membership_id",
    "member_id",
    "circle_id",
    "rotation_position",
    "status",
    "created_at",
    "updated_at",
  ],
});


crudRoutes({
  pathName: "cycles",
  table: "cycles",
  idColumn: "cycle_id",
  validate: validateCycle,
  columns: [
    "cycle_id",
    "circle_id",
    "cycle_number",
    "status",
    "starts_on",
    "ends_on",
    "created_at",
    "updated_at",
  ],
});

crudRoutes({
  pathName: "contributions",
  table: "contributions",
  idColumn: "contribution_id",
  validate: validateContribution,
  columns: [
    "contribution_id",
    "amount",
    "contribution_date",
    "payment_status",
    "membership_id",
    "cycle_id",
    "adjustment_note",
    "created_at",
    "updated_at",
  ],


  beforeWrite: async (body) => {
    const membership = await one(
      "SELECT membership_id FROM memberships WHERE membership_id = ?",
      [body.membership_id],
    );

    const cycle = await one("SELECT circle_id FROM cycles WHERE cycle_id = ?", [
      body.cycle_id,
    ]);

    if (!membership || !cycle) {
      const e = new Error("Referenced record does not exist");
      e.code = "ER_NO_REFERENCED_ROW_2";
      throw e;
    }

    const row = await one(
      `
      SELECT c.contribution_amount
      FROM circles c
      JOIN cycles cy ON cy.circle_id = c.circle_id
      WHERE cy.cycle_id = ?
    `,
      [body.cycle_id],
    );

    if (
      row &&
      Number(body.amount) !== Number(row.contribution_amount) &&
      !body.adjustment_note
    ) {
      const e = new Error(
        "Contribution amount must match the circle amount unless adjustment_note is supplied.",
      );
      e.code = "ER_CHECK_CONSTRAINT_VIOLATED";
      throw e;
    }
  },
});


crudRoutes({
  pathName: "payouts",
  table: "payouts",
  idColumn: "payout_id",
  validate: validatePayout,
  columns: [
    "payout_id",
    "amount",
    "payout_date",
    "status",
    "cycle_id",
    "membership_id",
    "created_at",
    "updated_at",
  ],



  beforeWrite: async (body) => {
    const membership = await one(
      "SELECT membership_id, circle_id, status FROM memberships WHERE membership_id = ?",
      [body.membership_id],
    );
    const cycle = await one(
      "SELECT cycle_id, circle_id FROM cycles WHERE cycle_id = ?",
      [body.cycle_id],
    );

    if (
      !membership ||
      !cycle ||
      Number(membership.circle_id) !== Number(cycle.circle_id) ||
      membership.status !== "active"
    ) {
      const e = new Error(
        "Membership must belong to the cycle circle and be active.",
      );
      e.code = "ER_NO_REFERENCED_ROW_2";
      throw e;
    }
  },
});

//        fixed rotation schedule.
app.post("/api/circles/:id/generate-schedule", async (req, res) => {
  const circleId = validateId(req.params.id);
  if (!circleId) return res.status(400).json({ error: "Invalid circle id" });

  const connection = await pool.getConnection();
  try {
    const [circleRows] = await connection.execute(
      "SELECT * FROM circles WHERE circle_id = ?",
      [circleId],
    );
    const circle = circleRows[0];
    if (!circle) return res.status(404).json({ error: "Circle not found" });

    const [memberships] = await connection.execute(
      `
      SELECT membership_id, rotation_position
      FROM memberships
      WHERE circle_id = ? AND status = 'active'
      ORDER BY rotation_position ASC
    `,
      [circleId],
    );

    if (!memberships.length) {
      return res
        .status(400)
        .json({ error: "Circle has no active memberships." });
    }

    await connection.beginTransaction();

    for (let i = 0; i < memberships.length; i++) {
      const cycleNumber = i + 1;
      await connection.execute(
        `INSERT INTO cycles (circle_id, cycle_number, status)
         VALUES (?, ?, 'scheduled')
         ON DUPLICATE KEY UPDATE cycle_id = LAST_INSERT_ID(cycle_id)`,
        [circleId, cycleNumber],
      );

      const [cycleRows] = await connection.execute(
        "SELECT cycle_id FROM cycles WHERE circle_id = ? AND cycle_number = ?",
        [circleId, cycleNumber],
      );

      const cycleId = cycleRows[0].cycle_id;
      //  const cycleId = cycleRows[0].id;

      await connection.execute(
        `INSERT INTO payouts (amount, status, cycle_id, membership_id)
         VALUES (?, 'pending', ?, ?)
         ON DUPLICATE KEY UPDATE payout_id = payout_id`,
        [
          Number(circle.contribution_amount) * memberships.length,
          cycleId,
          memberships[i].membership_id,
        ],
      );
    }

    await connection.commit();

    const [result] = await connection.execute(
      `
      SELECT cy.cycle_id, cy.cycle_number, cy.status,
             p.payout_id, p.amount AS payout_amount,
             p.membership_id AS recipient_membership_id
      FROM cycles cy
      LEFT JOIN payouts p ON p.cycle_id = cy.cycle_id
      WHERE cy.circle_id = ?
      ORDER BY cy.cycle_number
    `,
      [circleId],
    );

    res.status(201).json({ circle_id: circleId, cycles: result });
  } catch (err) {
    await connection.rollback();
    handleDbError(res, err);
  } finally {
    connection.release();
  }
});

app.use((req, res) => res.status(404).json({ error: "Route not found" }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});



pool
  .getConnection()
  .then(async (connection) => {
    connection.release();
    await pool.execute(`CREATE TABLE IF NOT EXISTS app_users (
      user_id BIGINT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(60) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL, role ENUM('ORGANIZER','MEMBER') NOT NULL,
      member_id INT NULL UNIQUE, account_status ENUM('ACTIVE','LOCKED','DISABLED') NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_app_user_member FOREIGN KEY (member_id) REFERENCES members(member_id)
    ) ENGINE=InnoDB`);
    await pool.execute(`CREATE TABLE IF NOT EXISTS app_sessions (
      session_id BIGINT AUTO_INCREMENT PRIMARY KEY, user_id BIGINT NOT NULL,
      token_hash CHAR(64) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP NULL,
      CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES app_users(user_id) ON DELETE CASCADE,
      INDEX idx_session_expiry (expires_at)
    ) ENGINE=InnoDB`);
    app.listen(PORT, () =>
      console.log(`ROSCA API listening on http://localhost:${PORT}`),
    );
  })
  .catch((err) => {
    console.error("Could not connect to MySQL:", err.message);
    process.exit(1);
  });

module.exports = app;
