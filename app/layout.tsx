import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import Image from 'next/image'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Metty Login',
  description: 'Metty login page',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="flex min-h-screen min-w-screen flex-col items-center justify-between">
          <div className="flex-1 flex w-full bg-black bg-[url('/banner2.jpg')] bg-cover bg-bottom items-center lg:items-start justify-center flex-col">
            <div className='flex justify-center p-8 bg-white rounded-3xl lg:flex-1 flex-col lg:rounded-none lg:flex lg:justify-center px-16 lg:w-2/6'>
              <div className='flex justify-center items-center mb-8'>
                <div className='bg-white rounded-full flex justify-center items-center p-4 pt-6'>
                  <div className='relative h-12 w-12 '>
                    <Image alt="" src={"/logo.svg"} fill/>
                  </div>
                </div>
              </div>
              <div className='flex flex-col flex-1 justify-center '>
                {children}
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>
  )
}
