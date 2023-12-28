"use client";
import { useEffect, useState } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import { useSearchParams } from 'next/navigation'

import { answerFIDOChallenge, confirmSignup, authWithMagicLink, answerMagicLinkChallenge, decodeMagicLinkHash, authUsernameless } from '@/app/actions';

import { useRouter } from 'next/navigation'

import Link from 'next/link';
import { EnvelopeIcon, FingerPrintIcon } from '@heroicons/react/24/outline';

export default function Home() {
  const [working, setWorking] = useState(false);
  const searchParams = useSearchParams();
  const router = useRouter()


  const doAuth = async () => {
    setWorking(true);
    try {
      const { response, error } = await authUsernameless();
      if (error) {
        console.error(error);
      } else {
        const authResp = await startAuthentication(response!);
        console.log('using user handle ', authResp.response.userHandle);
        const attResp = JSON.stringify(authResp);
        const resp = await answerFIDOChallenge(authResp.response.userHandle!, attResp);
        maybeRedirect(resp.AccessToken!, resp.RefreshToken!);
      }
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
    (async () => {

      var hash = window.location.hash.slice(1);
      if (hash !== undefined && hash.length > 0) {
        if (hash.includes('-')) {
          var code;
          [hash, code] = hash.split('=');
        }
        setWorking(true);
        var session = localStorage.getItem('session');
        const redirect = localStorage.getItem('redirect');
        const data = JSON.parse(await decodeMagicLinkHash(hash));
        try {
          if (code !== null) {
            await confirmSignup(data.userName, code!);
            console.log('account signed up');
          }
          if (session === null) {
            const { response, error } = await authWithMagicLink(data.userName, hash);
            if (error) {
              console.error(error);
              return;
            } else {
              maybeRedirect(response!.auth.AccessToken!, response!.auth.RefreshToken!, redirect);
            }
          } else {
            const { response, error } = await answerMagicLinkChallenge(data.userName, session!, hash);
            if (error) {
              console.error(error)
            } else {
              localStorage.removeItem('session');
              localStorage.removeItem('redirect');
              maybeRedirect(response!.AccessToken!, response!.RefreshToken!, redirect);
            }
          }
        } finally {
          setWorking(false);
        }
      }

    })();

  }, []);

  const formDisabled = (working);
  return (
    <main>
      <div className=' mb-8'>
        <h1 className='text-2xl text-black font-extrabold'>Access your account</h1>
        <p className='text-sm'>New user ? <Link className='underline' href={'/register'}>Create an account</Link></p>
      </div>
      <div className='my-4 flex flex-col'>
        <button type='button' disabled={formDisabled} onClick={(_) => doAuth()} className="flex-1 flex bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
          <FingerPrintIcon height={24} width={24} />
          <span className='flex-1'>Login with biometrics</span>
        </button>
        <p className="my-4 text-center before:content-[''] before:border-b-2 before:mb-2 before:mr-4 before:flex-1 flex flex-row flex-1 after:border-b-2 after:flex-1 after:mb-2 after:ml-4">or</p>

        <button type='button' onClick={(_) => router.push('/login/email')} className="flex-1 flex py-2 px-4 font-bold text-sm text-black rounded hover:enabled:bg-opacity-10 border-2 border-gray-600
        hover:enabled:bg-gray-500 disabled:opacity-30">
          <EnvelopeIcon height={24} width={24} />
          <span className='flex-1'>Login with email</span>
        </button>
      </div>
    </main>
  )
}
