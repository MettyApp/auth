"use client";
import { useState } from 'react';
import { authWithMagicLink } from '@/app/actions';

import { useRouter } from 'next/navigation'
import Link from 'next/link';
import { validateEmail } from '../validation';

export default function Home() {
  const [username, setUsername] = useState("");
  const [working, setWorking] = useState(false);
  const [done, setDone] = useState(false);
  const router = useRouter();

  const doAuth = async (username: string) => {
    setWorking(true);
    try {
      const { response, error } = await authWithMagicLink(username);
      if (error) {
        console.error(error);
      } else {
        setDone(true);
      }
    }
    finally {
      setWorking(false);
    }
  };

  const formDisabled = (working || done);
  const actionsDisabled = (working || !validateEmail(username));
  return (
    <main>
      <div className=' mb-8'>
        <h1 className='text-2xl text-black font-extrabold'>Access your account</h1>
        <p className='text-sm'>New user ? <Link className='underline' href={'/signup'}>Create an account</Link></p>
      </div>
      <form onSubmit={(e) => {
        e.preventDefault();
        if (!actionsDisabled) {
          doAuth(username);
        }
      }}>
        <div>
          <div className='my-4'>
            <label className="block text-gray-700 text-sm font-bold mb-1" htmlFor="email">
              Email
            </label>
            <input value={username} disabled={formDisabled} onChange={(e) => setUsername(e.target.value)} className="appearance-none border rounded w-full my-1 py-2 px-4 text-gray-700 leading-tight focus:outline-none" id="email" type="text" placeholder="Email" />
          </div>
        </div>
        <div className="flex items-center justify-between my-4">
          <button disabled={actionsDisabled} type='button' onClick={(_) => router.push('/signup')} className="bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
            Login
          </button>
          <button type='button' disabled={formDisabled} onClick={(_) => router.back()} className="font-bold text-sm text-black rounded disabled:opacity-30">
            Cancel
          </button>
        </div>
        {done && <p className='text-xs'> An email containing a login link has been sent to you.<br />
          Please check your inbox and follow the instructions to login to your account.<br />
          If you don&lsquot receive the email within a few minutes, please check your spam folder.</p>}
      </form>
    </main>
  )
}
