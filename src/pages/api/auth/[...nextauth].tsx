import { PrismaAdapter } from "@auth/prisma-adapter";
import NextAuth, { AuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";

import { MicrosoftEntraProvider } from "../../../next-auth-providers/MicrosoftEntraProvider";
import { prisma } from "../../../server/prisma";

const isGoogleAuthProviderConfigured = Boolean(
  typeof process.env.GOOGLE_CLIENT_ID === "string" &&
    typeof process.env.GOOGLE_CLIENT_SECRET === "string",
);

const googleProvider = GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
});

const isMicrosoftEntraProviderConfigured = Boolean(
  typeof process.env.MICROSOFT_ENTRA_CLIENT_ID === "string" &&
    typeof process.env.MICROSOFT_ENTRA_CLIENT_SECRET === "string" &&
    typeof process.env.MICROSOFT_ENTRA_ISSUER === "string",
);

const microsoftEntraProvider = MicrosoftEntraProvider({
  // Essentials > Application (client) ID
  clientId: process.env.MICROSOFT_ENTRA_CLIENT_ID!,
  // Certificates & secrets > Value
  clientSecret: process.env.MICROSOFT_ENTRA_CLIENT_SECRET!,
  // Endpoints > WS-Federation sign-on endpoint
  issuer: process.env.MICROSOFT_ENTRA_ISSUER!,
});

const adapter = PrismaAdapter(prisma);
const isDevelopment = process.env.NODE_ENV === "development";
const defaultLocalTestAccountEmail = "admin@workplacify.local";
const localTestAccountEmail =
  process.env.LOCAL_TEST_ACCOUNT_EMAIL ?? defaultLocalTestAccountEmail;
const localTestAccountPassword =
  process.env.LOCAL_TEST_ACCOUNT_PASSWORD ?? "password";

const localTestAccountProvider = CredentialsProvider({
  name: "Local Test Account",
  credentials: {
    email: {
      label: "Email",
      type: "email",
      value: localTestAccountEmail,
    },
    password: {
      label: "Password",
      type: "password",
    },
  },
  authorize: async (credentials) => {
    const email = credentials?.email;
    const password = credentials?.password;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email !== localTestAccountEmail ||
      password !== localTestAccountPassword
    ) {
      return null;
    }

    const user = await prisma.user.upsert({
      where: {
        email: localTestAccountEmail,
      },
      update: {
        emailVerified: new Date(),
        name: "Local Test Account",
      },
      create: {
        email: localTestAccountEmail,
        emailVerified: new Date(),
        name: "Local Test Account",
      },
    });

    return user;
  },
});

export const nextAuthOptions: AuthOptions = {
  adapter,
  session: {
    strategy: isDevelopment ? "jwt" : "database",
  },
  providers: [
    ...(isGoogleAuthProviderConfigured ? [googleProvider] : []),
    ...(isMicrosoftEntraProviderConfigured ? [microsoftEntraProvider] : []),
    ...(isDevelopment ? [localTestAccountProvider] : []),
  ],
  callbacks: {
    session: (props) => {
      const userId = props.user?.id ?? props.token?.sub;
      if (!userId) {
        return props.session;
      }
      return {
        ...props.session,
        user: {
          id: userId,
          ...props.session.user,
        },
      };
    },
  },
};
export default NextAuth(nextAuthOptions);
