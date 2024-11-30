import { FiUser, FiSearch, FiShoppingCart } from 'react-icons/fi';
import Link from 'next/link';
import './globals.css';
import { Dropdown, DropdownTrigger, DropdownMenu, DropdownItem,Button } from '@nextui-org/react';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { cookies } from 'next/headers';

export const metadata = {
  title: 'EC',
  description: 'Create by Group 8',
};

export default async function RootLayout({ children }) {
  const cookieStore = await cookies();
  const role = cookieStore.get('role')?.value || 'guest';
  console.log(role)
  return (
    <html lang="en">
      <body
        className={` h-full w-screen min-h-screen`}
      >
        <div className="w-full h-16 px-5 fixed  top-0 left-0 z-50 bg-white shadow-md">
          <div className="w-full grid h-full grid-cols-3">
            <Link
              href="/"
              className="w-1/3 h-full block !text-black font-semibold text-3xl"
            >
              Logo
            </Link>
            <div className="w-full h-full flex flex-row gap-1">
              <div className="w-1/4 text-center group h-full !text-black relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500 text-2xl">
                <Link href="/" className="w-full h-full block content-center">
                  Home
                </Link>
              </div>
              <div className="w-1/4 text-center group h-full !text-black relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500 text-2xl">
                <Link
                  href="/shop"
                  className="w-full h-full block content-center"
                >
                  Shop
                </Link>
              </div>
              <div className="w-1/4 text-center group h-full !text-black relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500 text-2xl">
                <Link
                  href="/about"
                  className="w-full h-full block content-center"
                >
                  About
                </Link>
              </div>
              <div className="w-1/4 text-center group h-full !text-black relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500 text-2xl">
                <Link href="/" className="w-full h-full block content-center">
                  Contact
                </Link>
              </div>
            </div>
            <div className="w-1/2 h-full flex flex-grow justify-between justify-self-end items-center">
              {role == 'admin' && <Dropdown>
                <DropdownTrigger>
                  <Button 
                    variant="bordered" 
                  >
                    <FiUser />
                  </Button>
                </DropdownTrigger>
                <DropdownMenu aria-label="Static Actions">
                  <DropdownItem key="new">New file</DropdownItem>
                  <DropdownItem key="copy">Copy link</DropdownItem>
                  <DropdownItem key="edit">Edit file</DropdownItem>
                  <DropdownItem key="delete" className="text-danger" color="danger">
                    Delete file
                  </DropdownItem>
                </DropdownMenu>
              </Dropdown>}
              {role == 'guest' && <Link
                href="/login"
                className="w-1/3 h-full flex items-center justify-center bg-transparent rounded-none relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500"
              >
                <FiUser />
              </Link>}
              
              <Button className="w-1/3 h-full flex items-center justify-center bg-transparent rounded-none relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500">
                <FiSearch />
              </Button>
              <Link
                href="/cart"
                className="w-1/3 h-full flex items-center justify-center bg-transparent rounded-none relative font-semibold after:absolute after:h-0 after:w-0 after:bg-sky-800 after:left-1/2 overflow-hidden after:bottom-0 after:hover:h-1 after:hover:w-1 after:translate-x-full after:hover:scale-x-[300] after:hover:transition-all after:hover:duration-500 after:transition-all after:duration-500 transition-all duration-500"
              >
                <FiShoppingCart />
              </Link>
            </div>
          </div>
        </div>
        <div className="w-full min-h-[calc(100vh-40px)] h-[calc(100vh-40px)] pt-16">
          {children}
        </div>
        <div className="w-full h-10 sticky bg-sky-800 text-white text-base">
          Footer
        </div>
        <ToastContainer />
      </body>
    </html>
  );
}
