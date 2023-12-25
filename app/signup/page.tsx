"use client";
import { useState } from 'react';
import { resendConfirmationCode, signUp } from '@/app/actions';
import { useRouter } from 'next/navigation'
import Link from 'next/link';
import { validateEmail } from '../validation';

export default function Home() {
  const [username, setUsername] = useState("");
  const [working, setWorking] = useState(false);
  const [done, setDone] = useState(false);
  const router = useRouter()

  const doSignUp = async (username: string) => {
    setWorking(true);
    try {
      const { error } = await signUp(username);
      if (error) {
        if (error === 'UsernameExistsException') {
          await doResendCode(username);
        } else {
          console.error(error);
          return;
        }
      }
      setDone(true);
    }
    catch (error: any) {
      console.error(error);
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


  const formDisabled = (working || done);
  const actionsDisabled = (working || username.length < 3 || !validateEmail(username));
  return (
    <main>
      <div className=' mb-8'>
        <h1 className='text-2xl text-black font-extrabold'>Create your account</h1>
        <p className='text-sm'>Already an user ? <Link className='underline' href={'/'}>Login to your account</Link></p>
      </div>
      <form onSubmit={(e) => {
        e.preventDefault();
        doSignUp(username);
      }}>
        <div className='mb-4'>
          <div>
            <label className="block text-gray-700 text-sm font-bold my-1" htmlFor="email">
              Email
            </label>
            <input value={username} disabled={formDisabled} onChange={(e) => setUsername(e.target.value)} className="appearance-none border rounded w-full my-1 py-2 px-4 text-gray-700 leading-tight focus:outline-none" id="email" type="text" placeholder="Email" />
          </div>
        </div>
        <div className="flex items-center justify-between mt-4 my-4">
          {!done && <button type='button' disabled={actionsDisabled} onClick={(_) => doSignUp(username)} className="bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
            Register
          </button>}
          {done && <button type='button' disabled={actionsDisabled} onClick={(_) => doResendCode(username)} className="bg-black hover:enabled:bg-black-700 text-white font-bold py-2 px-4 rounded focus:enabled:outline-none disabled:opacity-30 hover:enabled:bg-opacity-80">
            Resend email
          </button>}
          <button type='button' disabled={formDisabled} onClick={(_) => router.back()} className="font-bold text-sm text-black rounded disabled:opacity-30">
            Cancel
          </button>
        </div>
        {done && <p className='text-xs'> An email containing a confirmation link has been sent to the address you provided.<br />
          Please check your inbox and follow the instructions to activate your account.<br />
          If you don&lsquot receive the email within a few minutes, please check your spam folder.</p>}
      </form>
    </main>
  )
}
