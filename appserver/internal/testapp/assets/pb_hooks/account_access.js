// The project has exactly one account. It signs in with its password, the local
// key or a one-time code; every API still requires its token. The multi-account
// variant (a true $fixture.multiAccount() binding) allows other hosted accounts
// and their deletion.

function request(e) {
  // PocketBase treats an invalid bearer as anonymous; make expired or revoked
  // sessions an explicit failure rather than an anonymous request.
  if (!e.auth && e.request.header.get("Authorization")) {
    throw new UnauthorizedError("The session is invalid or expired.");
  }
  return e.next();
}

// Model-level, so it also covers superuser, dashboard and internal saves.
function multiAccount() {
  return typeof $fixture.multiAccount === "function" && $fixture.multiAccount();
}

function create(e) {
  if (multiAccount()) {
    return e.next();
  }
  const existing = e.app.findRecordsByFilter("users", "id != ''", "", 1, 0);
  if (existing.length) {
    throw new BadRequestError("This project already has its account; FixtureApp has exactly one.");
  }
  return e.next();
}

function remove(e) {
  // The multi-account variant lets core prune accounts that never signed in.
  if (multiAccount()) {
    return e.next();
  }
  throw new ForbiddenError("The project's account cannot be deleted.");
}

function realtime(e) {
  // Connection setup is anonymous; every record subscription requires the account.
  if (e.message.name === "PB_CONNECT") return e.next();
  if (!e.client.get("auth")) return;
  return e.next();
}

module.exports = {request, create, remove, realtime};
