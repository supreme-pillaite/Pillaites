import { lucia } from "@/auth";
import prisma from "@/lib/prisma";
import streamServerClient from "@/lib/stream";
import { signUpSchema, SignUpValues } from "@/lib/validation";
import { hash } from "@node-rs/argon2";
import { generateIdFromEntropySize } from "lucia";
import { isRedirectError } from "next/dist/client/components/redirect";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export async function signUp(
  credentials: SignUpValues,
): Promise<{ error: string }> {
  try {
    // Validate user input
    const { username, email, password } = signUpSchema.parse(credentials);

    // Check if username is already taken
    const existingUsername = await prisma.user.findFirst({
      where: {
        username: {
          equals: username,
          mode: "insensitive",
        },
      },
    });

    if (existingUsername) {
      return { error: "Username already taken" };
    }

    // Check if email is already registered
    const existingEmail = await prisma.user.findFirst({
      where: {
        email: {
          equals: email,
          mode: "insensitive",
        },
      },
    });

    if (existingEmail) {
      return { error: "Email already taken" };
    }

    // Hash the password
    const passwordHash = await hash(password, {
      memoryCost: 19456,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    });

    // Generate a unique user ID
    const userId = generateIdFromEntropySize(10);

    // Create the user and add them to Stream Server
    await prisma.$transaction(async (tx) => {
      await tx.user.create({
        data: {
          id: userId,
          username,
          displayName: username,
          email,
          passwordHash,
        },
      });

      await streamServerClient.upsertUser({
        id: userId,
        username,
        name: username,
      });
    });

    // Create a new session for the user
    const session = await lucia.createSession(userId, {});
    const sessionCookie = lucia.createSessionCookie(session.id);

    // Set the session cookie
    cookies().set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes,
    );

    // Redirect to the homepage
    return redirect("/");
  } catch (error) {
    // Handle errors
    if (isRedirectError(error)) throw error;

    console.error("Sign-up error:", error);
    return { error: "Something went wrong. Please try again." };
  }
}
