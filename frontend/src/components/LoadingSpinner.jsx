export default function LoadingSpinner({ size = 'large', text = 'Loading...' }) {
  const sizeClasses = {
    small: 'w-8 h-8',
    medium: 'w-12 h-12',
    large: 'w-16 h-16',
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-cyber-darker">
      <div className="text-center">
        <div className={`${sizeClasses[size]} border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto`}></div>
        {text && <p className="mt-4 text-gray-400 animate-pulse">{text}</p>}
      </div>
    </div>
  )
}
