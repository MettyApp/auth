import { NextRequest, NextResponse } from "next/server";
import { getSession } from './session';

const publicPaths = ['/login', '/register'];

export const middleware = async (request: NextRequest) => {
  const { pathname } = request.nextUrl
  try {
    const session = await getSession();
    if (session !== undefined) {
      if (publicPaths.some((prefix) => pathname.startsWith(prefix))) {
        return NextResponse.redirect(new URL('/profile', request.url));
      }
      return NextResponse.next();
    } else {
      if (!publicPaths.some((prefix) => pathname.startsWith(prefix))) {
        const dest = new URL('/login', request.url);
        dest.searchParams.append('then', request.url);
        return NextResponse.redirect(dest);
      }
      if (!pathname.startsWith('/login')) {
        return NextResponse.redirect(new URL('/login', request.url));
      }
    }
  }
  catch (err) {
    console.error(err);
    if (!pathname.startsWith('/login')) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
  }
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|logo.svg|banner2.jpg).*)"]
}
