// /middleware.ts

import { NextRequest, NextResponse } from "next/server";
import { getSession } from './session';

export const middleware = async (request: NextRequest) => {

  try {
    const session = await getSession();

    if (!session.isLoggedIn) {
      return NextResponse.redirect(new URL('/', request.url));
    }
  } catch {
    return NextResponse.redirect(new URL('/', request.url));
  }

}

export const config = {
  matcher: ["/profile"]
}