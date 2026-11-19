const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = process.env.GCP_PROJECT || "demo-no-project";
const FOUNDATION_ID = "zariya_khair_main";
const ADMIN_UID = "admin_uid_1";
const TREASURER_UID = "treasurer_uid_2";
const MEMBER_UID = "member_uid_3";
const ADMIN_EMAIL = "asifalquresh@gmail.com";

const [emulatorHost, emulatorPortStr] = (
  process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085"
).split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

before(async () => {
  const rules = fs.readFileSync("./firestore.rules", "utf8");
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules,
      host: emulatorHost,
      port: emulatorPort,
    },
  });
});

after(async () => {
  if (testEnv) await testEnv.cleanup();
});

beforeEach(async () => {
  if (testEnv) await testEnv.clearFirestore();
});

async function seedRoles() {
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    const past = new Date(Date.now() - 10000);
    await db.collection("users").doc(ADMIN_UID).set({
      uid: ADMIN_UID,
      email: ADMIN_EMAIL,
      displayName: "Foundation Admin",
      role: "ADMIN",
      createdAt: past,
      updatedAt: past,
    });
    await db.collection("users").doc(TREASURER_UID).set({
      uid: TREASURER_UID,
      email: "treasurer@zariyakhair.org",
      displayName: "Foundation Treasurer",
      role: "TREASURER",
      createdAt: past,
      updatedAt: past,
    });
    await db.collection("users").doc(MEMBER_UID).set({
      uid: MEMBER_UID,
      email: "member@zariyakhair.org",
      displayName: "Foundation Member",
      role: "MEMBER",
      createdAt: past,
      updatedAt: past,
    });
  });
}

test("Unauthenticated users cannot read or write any collection", async () => {
  const unauthDb = testEnv.unauthenticatedContext().firestore();
  await assertFails(
    unauthDb.collection("donations").where("foundationId", "==", FOUNDATION_ID).get()
  );
  await assertFails(
    unauthDb.collection("members").where("foundationId", "==", FOUNDATION_ID).get()
  );
});

test("User registration prevents self-escalation unless bootstrap admin", async () => {
  const past = new Date(Date.now() - 1000);
  const memberDb = testEnv
    .authenticatedContext(MEMBER_UID, { email: "member@zariyakhair.org", email_verified: true })
    .firestore();

  await assertFails(
    memberDb.collection("users").doc(MEMBER_UID).set({
      uid: MEMBER_UID,
      email: "member@zariyakhair.org",
      displayName: "Attacker",
      role: "ADMIN",
      createdAt: past,
      updatedAt: past,
    })
  );

  await assertSucceeds(
    memberDb.collection("users").doc(MEMBER_UID).set({
      uid: MEMBER_UID,
      email: "member@zariyakhair.org",
      displayName: "Regular Member",
      role: "MEMBER",
      createdAt: past,
      updatedAt: past,
    })
  );

  const adminDb = testEnv
    .authenticatedContext(ADMIN_UID, { email: ADMIN_EMAIL, email_verified: true })
    .firestore();
  await assertSucceeds(
    adminDb.collection("users").doc(ADMIN_UID).set({
      uid: ADMIN_UID,
      email: ADMIN_EMAIL,
      displayName: "Asif Admin",
      role: "ADMIN",
      createdAt: past,
      updatedAt: past,
    })
  );
});

test("PII Isolation: Non-owner members cannot read another member's private contact doc", async () => {
  await seedRoles();
  const past = new Date(Date.now() - 1000);
  const adminDb = testEnv
    .authenticatedContext(ADMIN_UID, { email: ADMIN_EMAIL, email_verified: true })
    .firestore();
  const treasurerDb = testEnv.authenticatedContext(TREASURER_UID).firestore();
  const memberDb = testEnv.authenticatedContext(MEMBER_UID).firestore();

  await assertSucceeds(
    adminDb.collection("members").doc("mem_1").set({
      foundationId: FOUNDATION_ID,
      fullName: "Imran Khan",
      village: "Rampur",
      tehsil: "Sadar",
      district: "Aligarh",
      city: "Aligarh",
      role: "MEMBER",
      active: true,
      joinedDateMillis: Date.now() - 5000,
      createdByUid: ADMIN_UID,
      createdAt: past,
      updatedAt: past,
    })
  );

  await assertSucceeds(
    adminDb.collection("members").doc("mem_1").collection("private").doc("contact").set({
      mobileNumber: "+91 9876543210",
      address: "House 12, Rampur",
      email: "imran@example.com",
      createdByUid: ADMIN_UID,
      createdAt: past,
      updatedAt: past,
    })
  );

  // Treasurer can read PII contact; unrelated member cannot
  await assertSucceeds(
    treasurerDb.collection("members").doc("mem_1").collection("private").doc("contact").get()
  );
  await assertFails(
    memberDb.collection("members").doc("mem_1").collection("private").doc("contact").get()
  );
  // Directory listing succeeds for foundation members
  await assertSucceeds(
    memberDb.collection("members").where("foundationId", "==", FOUNDATION_ID).get()
  );
});

test("Donations & Expenses: Treasurer/Admin can write; Members can read transparently but not write", async () => {
  await seedRoles();
  const past = new Date(Date.now() - 1000);
  const treasurerDb = testEnv.authenticatedContext(TREASURER_UID).firestore();
  const memberDb = testEnv.authenticatedContext(MEMBER_UID).firestore();

  await assertSucceeds(
    treasurerDb.collection("donations").doc("don_1").set({
      foundationId: FOUNDATION_ID,
      memberId: "mem_1",
      memberName: "Imran Khan",
      amount: 5000.0,
      dateMillis: Date.now() - 5000,
      paymentMethod: "UPI",
      transactionId: "UPI123456",
      notes: "Monthly contribution",
      recordedByUid: TREASURER_UID,
      recordedByName: "Foundation Treasurer",
      createdAt: past,
      updatedAt: past,
    })
  );

  await assertFails(
    memberDb.collection("donations").doc("don_2").set({
      foundationId: FOUNDATION_ID,
      memberId: "mem_1",
      memberName: "Imran Khan",
      amount: 5000.0,
      dateMillis: Date.now() - 5000,
      paymentMethod: "UPI",
      transactionId: "UPI999",
      recordedByUid: MEMBER_UID,
      recordedByName: "Member",
      createdAt: past,
      updatedAt: past,
    })
  );

  await assertSucceeds(
    memberDb.collection("donations").where("foundationId", "==", FOUNDATION_ID).get()
  );
});

test("Audit logs are append-only and cannot be modified or deleted", async () => {
  await seedRoles();
  const past = new Date(Date.now() - 1000);
  const adminDb = testEnv
    .authenticatedContext(ADMIN_UID, { email: ADMIN_EMAIL, email_verified: true })
    .firestore();

  await assertSucceeds(
    adminDb.collection("audit_logs").doc("log_1").set({
      foundationId: FOUNDATION_ID,
      actorUid: ADMIN_UID,
      actorName: "Foundation Admin",
      actorRole: "ADMIN",
      action: "CREATE",
      targetCollection: "members",
      targetId: "mem_1",
      summary: "Added member Imran Khan",
      timestampMillis: Date.now() - 5000,
      createdAt: past,
    })
  );

  await assertFails(
    adminDb.collection("audit_logs").doc("log_1").update({ summary: "Tampered" })
  );
  await assertFails(adminDb.collection("audit_logs").doc("log_1").delete());
});
