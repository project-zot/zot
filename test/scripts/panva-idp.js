import Provider from "oidc-provider";
import express from "express";

const port = process.argv[2] ? Number(process.argv[2]) : 5556;
const cb_url = process.argv[3] ? process.argv[3] : 'http://127.0.0.1:5555/callback';

// ---- Simple in-memory user store ----
const users = [
  {
    id: "1",
    username: "alice",
    password: "password",
    claims: {
      sub: "1",
      email: "alice@example.com",
      email_verified: true,
      preferred_username: "alice",
      name: "Alice",
      groups: ["admin", "dev"],
    },
  },
];

// ---- Account adapter for oidc-provider ----
const Account = {
  async findAccount(ctx, id) {
    const user = users.find((u) => u.id === id);
    if (!user) return undefined;

    return {
      accountId: id,
      async claims(use, scope) {
        console.log(`[IDP] Account.claims called with use=${use} scope=${scope}`);
        return {
          sub: user.claims.sub,
          email: user.claims.email,
          email_verified: user.claims.email_verified,
          preferred_username: user.claims.preferred_username,
          name: user.claims.name,
          groups: user.claims.groups,
        };
      },
    };
  },

  async authenticate(username, password) {
    return users.find(
      (u) => u.username === username && u.password === password
    );
  },
};

// ---- OIDC provider configuration ----
const configuration = {
  clients: [{
    client_id: 'zot-client',
    client_secret: 'ZXhhbXBsZS1hcHAtc2VjcmV0',
    redirect_uris: ['http://dummy'], // Will be overridden dynamically
    response_types: ["code"],
    grant_types: ["authorization_code"],
    token_endpoint_auth_method: "client_secret_basic",
    scope: "openid profile email groups",
  }],

  features: {
    devInteractions: { enabled: false }, // we provide our own login
    introspection: { enabled: true },
    revocation: { enabled: true },
    resourceIndicators: { enabled: false },
    // claimsParameter is now automatically supported
  },

  interactions: {
    url(ctx, interaction) {
      return `/login?uid=${interaction.uid}`;
    },
  },

  async findAccount(ctx, id) {
    return Account.findAccount(ctx, id);
  },

  // Required for ZITADEL: return standard claims
  scopes: ["openid", "profile", "email", "groups"],
  claims: {
    openid: ["sub"],
    profile: ["name", "preferred_username"],
    email: ["email", "email_verified"],
    groups: ["groups"],
  },

  async renderError(ctx, out, error) {
    ctx.body = `OIDC Error: ${error.error_description}`;
  },
};

// ---- Create provider ----
const issuer = `http://127.0.0.1:${port}/`;
const provider = new Provider(issuer, configuration);

// Monkey-patch Client prototype to allow dynamic redirect URIs
const Client = provider.Client;
const originalRedirectUriAllowed = Client.prototype.redirectUriAllowed;

Client.prototype.redirectUriAllowed = function(value) {
  // Allow any localhost URI for testing
  try {
    const parsed = new URL(value);
    if (parsed.hostname === '127.0.0.1' && parsed.pathname === '/zot/auth/callback/oidc') {
      return true;
    }
  } catch (e) {
    // ignore invalid URLs
  }
  return originalRedirectUriAllowed.call(this, value);
};

provider.Client.find('zot-client').then(client => {
  console.log('Startup check: Client found:', client ? 'yes' : 'no');
}).catch(err => console.error('Startup check error:', err));

// ---- Simple login UI ----
const app = express();
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  console.log(`[IDP] Request: ${req.method} ${req.url}`);
  next();
});

app.get("/login", async (req, res) => {
  console.log("Hit /login endpoint");
  const { uid } = req.query;
  const user = users[0];

  const result = await provider.interactionDetails(req, res);
  console.log("Interaction details:", result);
  if (result.prompt.details) {
    console.log("Prompt details:", JSON.stringify(result.prompt.details, null, 2));
  }

  if (result.prompt.name === 'login') {
    await provider.interactionFinished(
      req,
      res,
      {
        login: {
          accountId: user.id,
        },
      },
      { mergeWithLastSubmission: false }
    );
  } else {
    // Manually create a grant to ensure scopes are accepted
    const grant = new provider.Grant({
      accountId: result.session.accountId,
      clientId: result.params.client_id,
    });
    
    const scopes = result.params.scope.split(' ');
    console.log(`[IDP] Manually granting scopes: ${scopes.join(' ')}`);
    grant.addOIDCScope(scopes.join(' '));
    
    const grantId = await grant.save();
    
    await provider.interactionFinished(
      req,
      res,
      { consent: { grantId } },
      { mergeWithLastSubmission: true }
    );
  }
  console.log("Interaction finished");
});

// app.post("/login", async (req, res, next) => { ... });

// ---- mount OIDC provider ----
app.use(provider.callback());
app.listen(port, () => {
  console.log(`OIDC Provider listening at ${issuer}`);
});

