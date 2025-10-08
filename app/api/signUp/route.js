import { prisma } from "../../../prisma/db";
import bcrypt from "bcryptjs";

export const dynamic = "force-dynamic";

export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON" }),
      { status: 400 }
    );
  }

  const { username, password, confirmPassword } = body;

  if (!username || !password || !confirmPassword) {
    return new Response(
      JSON.stringify({ error: "All fields are required" }),
      { status: 400 }
    );
  }

  if (password !== confirmPassword) {
    return new Response(
      JSON.stringify({ error: "Passwords do not match" }),
      { status: 400 }
    );
  }

  const existing = await prisma.user.findFirst({
    where: { name: username },
  });

  if (existing) {
    return new Response(
      JSON.stringify({ error: "User already exists" }),
      { status: 400 }
    );
  }

  const hash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: { name: username, password: hash },
  });

  return new Response(
    JSON.stringify({
      data: { id: user.id, name: user.name },
      message: "User created successfully",
    }),
    {
      status: 201,
      headers: { "Content-Type": "application/json" },
    }
  );
}

