const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = process.env.GCP_PROJECT || "demo-no-project";
const ALICE_UID = "alice_123";
const BOB_UID = "bob_456";
const CHARLIE_UID = "charlie_789";

const [emulatorHost, emulatorPortStr] = (process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085").split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

function nowTs() {
  return new Date(Date.now() - 1000);
}

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
  if (testEnv) {
    await testEnv.cleanup();
  }
});

beforeEach(async () => {
  if (testEnv) {
    await testEnv.clearFirestore();
  }
});

test("Unauthenticated user cannot read or write profiles, conversations, or groups", async () => {
  const unauthDb = testEnv.unauthenticatedContext().firestore();
  await assertFails(unauthDb.collection("user_public").where("isDiscoverable", "==", true).get());
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).get());
  await assertFails(unauthDb.collection("conversations").where("participantIds", "array-contains", ALICE_UID).get());
  await assertFails(unauthDb.collection("groups").where("memberIds", "array-contains", ALICE_UID).get());
});

test("Private profile PII isolation: Bob cannot read Alice's private profile", async () => {
  const ts = nowTs();
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    await ctx.firestore().collection("users").doc(ALICE_UID).set({
      userId: ALICE_UID,
      email: "alice@example.com",
      phoneNumber: "+2348012345678",
      countryCode: "+234",
      isPhoneVerified: false,
      preferredLanguage: "ha",
      themeMode: "system",
      notificationsEnabled: true,
      allowPhoneSearch: false,
      readReceiptsEnabled: true,
      createdAt: ts,
      updatedAt: ts,
    });
  });

  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();

  await assertSucceeds(aliceDb.collection("users").doc(ALICE_UID).get());
  await assertFails(bobDb.collection("users").doc(ALICE_UID).get());
  await assertFails(bobDb.collection("users").get());
});

test("Phone verification spoofing blocked: cannot set isPhoneVerified=true without matching phone token", async () => {
  const ts = nowTs();
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();

  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).set({
      userId: ALICE_UID,
      phoneNumber: "+2348012345678",
      countryCode: "+234",
      isPhoneVerified: true,
      preferredLanguage: "ha",
      themeMode: "system",
      notificationsEnabled: true,
      allowPhoneSearch: false,
      readReceiptsEnabled: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).set({
      userId: ALICE_UID,
      phoneNumber: "+2348012345678",
      countryCode: "+234",
      isPhoneVerified: false,
      preferredLanguage: "ha",
      themeMode: "system",
      notificationsEnabled: true,
      allowPhoneSearch: false,
      readReceiptsEnabled: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );
});

test("Public profile rejects phone exposure when allowPhoneSearch is false and rejects ghost fields", async () => {
  const ts = nowTs();
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();

  await assertFails(
    aliceDb.collection("user_public").doc(ALICE_UID).set({
      userId: ALICE_UID,
      displayName: "Alice",
      username: "alice_ng",
      allowPhoneSearch: false,
      searchablePhone: "+2348012345678",
      isDiscoverable: true,
      isOnline: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  await assertFails(
    aliceDb.collection("user_public").doc(ALICE_UID).set({
      userId: ALICE_UID,
      displayName: "Alice",
      username: "alice_ng",
      allowPhoneSearch: false,
      searchablePhone: "",
      isDiscoverable: true,
      isOnline: true,
      isVerifiedAdmin: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  await assertSucceeds(
    aliceDb.collection("user_public").doc(ALICE_UID).set({
      userId: ALICE_UID,
      displayName: "Alice",
      username: "alice_ng",
      allowPhoneSearch: false,
      searchablePhone: "",
      isDiscoverable: true,
      isOnline: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );
});

test("Direct conversations & messages enforce participant isolation", async () => {
  const ts = nowTs();
  const convId = `${ALICE_UID}_${BOB_UID}`;
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const charlieDb = testEnv.authenticatedContext(CHARLIE_UID).firestore();

  await assertSucceeds(
    aliceDb.collection("conversations").doc(convId).set({
      participantIds: [ALICE_UID, BOB_UID],
      participantNames: { [ALICE_UID]: "Alice", [BOB_UID]: "Bob" },
      lastMessageText: "",
      lastMessageType: "text",
      unreadCounts: { [ALICE_UID]: 0, [BOB_UID]: 0 },
      createdBy: ALICE_UID,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  await assertSucceeds(
    aliceDb.collection("conversations").doc(convId).collection("messages").doc("msg_1").set({
      conversationId: convId,
      senderId: ALICE_UID,
      senderName: "Alice",
      participantIds: [ALICE_UID, BOB_UID],
      text: "Sannu Bob!",
      messageType: "text",
      status: "sent",
      createdAt: ts,
      updatedAt: ts,
    })
  );

  await assertSucceeds(
    bobDb.collection("conversations").doc(convId).collection("messages")
      .where("participantIds", "array-contains", BOB_UID).get()
  );

  await assertFails(
    charlieDb.collection("conversations").doc(convId).get()
  );

  await assertFails(
    charlieDb.collection("conversations").doc(convId).collection("messages").get()
  );

  await assertFails(
    charlieDb.collection("conversations").doc(convId).collection("messages").doc("msg_1").get()
  );

  await assertFails(
    charlieDb.collection("conversations").doc(convId).collection("messages").doc("msg_2").set({
      conversationId: convId,
      senderId: CHARLIE_UID,
      senderName: "Charlie",
      participantIds: [ALICE_UID, CHARLIE_UID],
      text: "Intruder",
      messageType: "text",
      status: "sent",
      createdAt: ts,
      updatedAt: ts,
    })
  );
});

test("Groups enforce admin-only posting and membership boundaries", async () => {
  const ts = nowTs();
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const charlieDb = testEnv.authenticatedContext(CHARLIE_UID).firestore();

  await assertSucceeds(
    aliceDb.collection("groups").doc("grp_1").set({
      name: "Kano Developers",
      description: "Engineering community",
      ownerId: ALICE_UID,
      adminIds: [ALICE_UID],
      memberIds: [ALICE_UID, BOB_UID],
      memberNames: { [ALICE_UID]: "Alice", [BOB_UID]: "Bob" },
      onlyAdminsCanPost: true,
      onlyAdminsCanAddMembers: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Admin can post even when onlyAdminsCanPost is true
  await assertSucceeds(
    aliceDb.collection("groups").doc("grp_1").collection("messages").doc("gmsg_1").set({
      groupId: "grp_1",
      senderId: ALICE_UID,
      senderName: "Alice",
      memberIds: [ALICE_UID, BOB_UID],
      text: "Barka da zuwa!",
      messageType: "text",
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Regular member Bob cannot post when onlyAdminsCanPost is true
  await assertFails(
    bobDb.collection("groups").doc("grp_1").collection("messages").doc("gmsg_2").set({
      groupId: "grp_1",
      senderId: BOB_UID,
      senderName: "Bob",
      memberIds: [ALICE_UID, BOB_UID],
      text: "Unauthorized post",
      messageType: "text",
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Non-member Charlie cannot read the group
  await assertFails(charlieDb.collection("groups").doc("grp_1").get());
});
