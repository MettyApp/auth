"use client";

import { useEffect, useState } from 'react';
import { addAuthenticator, getUser, register, registerUsernameless, removeAuthenticator } from '../actions';
import { GetUserCommandOutput } from '@aws-sdk/client-cognito-identity-provider';
import { startRegistration } from '@simplewebauthn/browser';
import { useRouter } from 'next/navigation';
import { XMarkIcon } from '@heroicons/react/24/solid'

interface Authenticator {
  credentialID: Buffer
  credentialPublicKey: Buffer
}

const authenticatorId = (authenticator: Authenticator) => authenticator.credentialID.toString('base64');

function Authenticator({ authenticator }: { authenticator: Authenticator }) {
  const deviceId = authenticatorId(authenticator);
  const doRemoveAuthenticator = async (id: string) => {
    const accessToken = localStorage.getItem('accessToken');
    if (accessToken == null) {
      throw new Error('access token missing');
    }
    await removeAuthenticator(accessToken, id);
  }

  return <li className='group text-black flex flex-row justify-between hover:bg-gray-100 rounded-full pr-4 py-2'>
    {authenticator.credentialID.toString('base64')}
    <button className='h-6 w-6 group-hover:block hidden'><XMarkIcon onClick={(_) => doRemoveAuthenticator(deviceId)} /></button>
  </li>
}

export default function Profile() {
  const [userProfile, setUserProfile] = useState<GetUserCommandOutput | null>(null);
  const [working, setWorking] = useState(false);
  const router = useRouter();

  const doLogout = async () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    router.replace('/');
  }
  const enrollDevice = async () => {
    setWorking(true);
    const accessToken = localStorage.getItem('accessToken');
    if (accessToken == null) {
      throw new Error('access token missing');
    }
    try {
      const opts = await registerUsernameless(accessToken)
      const attResp = JSON.stringify(await startRegistration(opts));
      await addAuthenticator(accessToken, attResp);
    } finally { setWorking(false); }
  };

  useEffect(() => {
    const accessToken = localStorage.getItem('accessToken');
    if (accessToken != "") {
      (async () => {
        try {
          const user = await getUser(accessToken!);
          setUserProfile(user);
        } catch {
          router.replace('/');
        }
      })();
    } else {
      localStorage.removeItem('accessToken');
      router.replace('/');
    }
  }, []);

  const authenticators: Array<Authenticator> = JSON.parse(userProfile?.UserAttributes?.find((e) => e.Name == 'custom:publicKeyCred')?.Value || '[]').map((e: any) => ({ credentialID: Buffer.from(e.credentialID), credentialPublicKey: Buffer.from(e.credentialPublicKey) }));
  const email = userProfile?.UserAttributes?.find((e) => e.Name == 'email')?.Value;
  return (<main>
    <h1 className='text-2xl text-black font-extrabold mb-8'>Hello, {email}</h1>
    <div className='my-4'>
      <h2 className='text-black font-bold'>Registered authenticators</h2>
      <ul className='list-disc list-inside mt-4'>
        {authenticators.map((e) => <Authenticator key={authenticatorId(e)} authenticator={e} />)}
      </ul>
    </div>
    <div className='flex flex-row justify-between'>
      <button type='button' disabled={working || email == null} onClick={(_) => enrollDevice()} className="font-bold text-sm text-black rounded disabled:opacity-30">
        Add current device
      </button>
      <button type='button' disabled={working || email == null} onClick={(_) => doLogout()} className="bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
        Logout
      </button>
    </div>
  </main>);
}