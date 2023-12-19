"use client";
import { useEffect, useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { useSearchParams } from 'next/navigation'

import { signUp, register, auth, answerFIDOChallenge, confirmSignup, resendConfirmationCode, authWithMagicLink, answerMagicLinkChallenge, authWithRefreshToken, getUser, decodeMagicLinkHash } from '@/app/actions';
import { jwtDecode } from 'jwt-decode';

import { useRouter } from 'next/navigation'

export default function Home() {
  const [username, setUsername] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");
  const [code, setCode] = useState("");
  const [working, setWorking] = useState(false);
  const [shouldConfirm, setShouldConfirm] = useState(false);
  const searchParams = useSearchParams();
  const router = useRouter()

  const saveTokens = (accessToken: string, refreshToken: string) => {
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
  }

  const loadTokens = async (): Promise<{ accessToken: string | null, refreshToken: string | null }> => {
    const now = Math.round((new Date()).getTime() / 1000);
    const accessToken = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    if (refreshToken != null) {
      setRefreshToken(refreshToken);
      if (accessToken != null) {
        const decoded = jwtDecode(accessToken);
        if ((decoded.exp ?? 0) <= now || ((decoded.iat ?? 0) >= now)) {
          // token expired or malformed
          console.log('access token expired ');
          try {
            const accessToken = (await authWithRefreshToken(decoded.sub!, refreshToken)).response!;
            console.log('refreshed access token');
            saveTokens(accessToken, refreshToken);
            setAccessToken(accessToken);
          } catch {
            console.log('refresh token expired');
            localStorage.removeItem('refreshToken');
            localStorage.removeItem('accessToken');
          }
        } else {
          console.log('access token still valid');
          setAccessToken(accessToken);
        }
      }
    }
    return { accessToken, refreshToken };
  };

  const doRegistration = async (username: string) => {
    setWorking(true);
    try {
      const opts = await register(username);
      const attResp = JSON.stringify(await startRegistration(opts));
      await signUp(username, attResp);
      setShouldConfirm(true);
    }
    catch (error: any) {
      console.error(error);
    }
    finally {
      setWorking(false);
    }
  };

  const doAuth = async (username: string) => {
    setWorking(true);
    try {
      const { response, error } = await auth(username);
      if (error) {
        if (error == 'UserNotConfirmedException') {
          setShouldConfirm(true);
        }
      } else {
        const { session, challengeParameters } = response;
        const v = JSON.parse(challengeParameters);
        const authResp = await startAuthentication(v);
        console.log('using user handle ', authResp.response.userHandle);
        const attResp = JSON.stringify(authResp);
        const resp = await answerFIDOChallenge(username, session, attResp);
        saveTokens(resp.AccessToken!, resp.RefreshToken!);
        maybeRedirect(resp.AccessToken!, resp.RefreshToken!);
      }
    }
    finally {
      setWorking(false);
    }
  };
  const doEmailAuth = async (username: string) => {
    setWorking(true);
    try {
      const { response, error } = await authWithMagicLink(username);
      if (error) {
        if (error == 'UserNotConfirmedException') {
          setShouldConfirm(true);
        }
      } else {
        const { session, challengeParameters } = response;
        localStorage.setItem('session', session);
        if (searchParams.get('redirect') != null) {
          localStorage.setItem('redirect', searchParams.get('redirect')!);
        }
        console.log('email sent to ', challengeParameters);
      }
    }
    finally {
      setWorking(false);
    }
  };

  const doConfirm = async (username: string, code: string) => {
    setWorking(true);
    try {
      const { error } = await confirmSignup(username, code);
      if (error) {
        setCode('');
      } else {
        setShouldConfirm(false);
      }
    }
    catch (error: any) {
      console.error(error.message);
    }
    finally {
      setWorking(false);
    }
  };
  const doResendCode = async (username: string) => {
    setWorking(true);
    try {
      await resendConfirmationCode(username);
    }
    catch (error: any) {
      console.error(error.message);
    }
    finally {
      setWorking(false);
    }
  };

  const maybeRedirect = (accessToken: string, refreshToken: string, redirect = searchParams.get('redirect')) => {
    const hash = window.location.hash.slice(1);
    if (hash !== undefined && hash.length > 0) {
      window.location.hash = '';
    }

    if (redirect === null) {
      router.replace('/profile');
      return;
    }
    console.log('considering redirect to ' + redirect);
    const url = new URL(redirect);
    if (!['http:', 'metty:'].includes(url.protocol)) {
      console.error('refusing to redirect to protocol ' + url.protocol);
      return
    }
    if (url.protocol === 'http:' && !url.host.startsWith('localhost:')) {
      console.error(`refusing to redirect to http protocol when host is not localhost (host is ${url.host})`);
      return;
    }
    url.searchParams.append('accessToken', accessToken);
    url.searchParams.append('refreshToken', refreshToken);
    window.location.assign(url.toString());
  };

  useEffect(() => {
    if (accessToken != "") {
      (async () => {
        const user = await getUser(accessToken);
        const email = user.UserAttributes?.find((e) => e.Name == 'email')?.Value!;
        setUsername(email);
      })();
    }
  }, [accessToken]);

  useEffect(() => {
    (async () => {
      const { accessToken, refreshToken } = await loadTokens();
      if (accessToken == null || accessToken.length === 0) {
        const hash = window.location.hash.slice(1);
        if (hash !== undefined && hash.length > 0) {
          setWorking(true);
          var session = localStorage.getItem('session');
          const redirect = localStorage.getItem('redirect');
          const data = JSON.parse(await decodeMagicLinkHash(hash));
          try {
            if (session === null) {
              const { response, error } = await authWithMagicLink(data.userName, hash);
              if (error) {
                if (error == 'UserNotConfirmedException') {
                  setShouldConfirm(true);
                } else {
                  console.error(error);
                }
                return;
              } else {
                saveTokens(response!.auth.AccessToken!, response!.auth.RefreshToken!);
                maybeRedirect(response!.auth.AccessToken!, response!.auth.RefreshToken!, redirect);
              }
            } else {
              const { response, error } = await answerMagicLinkChallenge(data.userName, session!, hash);
              if (error) {
                console.error(error)
              } else {
                localStorage.removeItem('session');
                localStorage.removeItem('redirect');
                saveTokens(response!.AccessToken!, response!.RefreshToken!);
                maybeRedirect(response!.AccessToken!, response!.RefreshToken!, redirect);
              }
            }
          } finally {
            setWorking(false);
          }
        }
      } else {
        maybeRedirect(accessToken!, refreshToken!);
        setWorking(false);
      }
    })();

  }, []);

  const formDisabled = (accessToken.length > 0 || working);
  const actionsDisabled = (accessToken.length > 0 || working || username.length === 0);
  return (
    <main>
      <h1 className='text-2xl text-black font-extrabold mb-8'>Access your account</h1>
      <form onSubmit={(e) => {
        e.preventDefault();
        shouldConfirm ? doConfirm(username, code) : doAuth(username)
      }}>
        <div>
          <div>
            <label className="block text-gray-700 text-sm font-bold my-1" htmlFor="email">
              Email
            </label>
            <input value={username} disabled={formDisabled || shouldConfirm} onChange={(e) => setUsername(e.target.value)} className="appearance-none border rounded w-full my-1 py-2 px-4 text-gray-700 leading-tight focus:outline-none" id="email" type="text" placeholder="Email" />
          </div>
          {shouldConfirm &&
            <div className="my-2">
              <label className="block text-gray-700 text-sm font-bold my-1" htmlFor="code">
                Confirmation code
              </label>
              <input value={code} disabled={formDisabled} onChange={(e) => setCode(e.target.value)} className="appearance-none border rounded w-full py-2 px-4 my-1 text-gray-700 leading-tight focus:outline-none" id="code" type="text" placeholder="Code" />
            </div>}
        </div>
        {shouldConfirm ? (<div className="flex items-center justify-between mt-8 my-4">
          <button type='button' disabled={actionsDisabled || code.length === 0} onClick={(_) => doConfirm(username, code)} className="bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
            Confirm
          </button>
          <button type='button' disabled={actionsDisabled} onClick={(_) => doResendCode(username)} className="py-2 px-4 font-bold text-sm text-black rounded hover:enabled:bg-opacity-10
        hover:enabled:bg-gray-500 disabled:opacity-30">
            Resend code
          </button>
        </div>) : ((<div className="flex items-center justify-between mt-8 my-4">
          <button type='button' disabled={actionsDisabled || username.length === 0} onClick={(_) => doAuth(username)} className="bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
            Login
          </button>
          <button type='button' disabled={actionsDisabled || username.length === 0} onClick={(_) => doRegistration(username)} className="py-2 px-4 font-bold text-sm text-black rounded hover:enabled:bg-opacity-10
        hover:enabled:bg-gray-500 disabled:opacity-30">
            Create an account
          </button>
        </div>))}
        <button type='button' disabled={actionsDisabled || username.length === 0} onClick={(_) => doEmailAuth(username)} className="font-bold text-sm text-black rounded disabled:opacity-30">
          Send me a link by email
        </button>

      </form>
    </main>
  )
}
