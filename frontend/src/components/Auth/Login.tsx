export default function Login() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-sinx-darker via-sinx-dark to-sinx-darker flex items-center justify-center">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gradient mb-2">sinX Threat Hunter</h1>
          <p className="text-gray-400">Enterprise Threat Hunting Platform</p>
        </div>
        <form className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Username</label>
            <input
              type="text"
              className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 focus:outline-none focus:border-sinx-primary"
              placeholder="Enter your username"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Password</label>
            <input
              type="password"
              className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 focus:outline-none focus:border-sinx-primary"
              placeholder="Enter your password"
            />
          </div>
          <button
            type="submit"
            className="w-full bg-gradient-to-r from-sinx-primary to-sinx-secondary text-white font-semibold py-2 rounded hover:opacity-90 transition"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  )
}
