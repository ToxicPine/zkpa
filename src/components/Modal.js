export const SuccessDialog = ({ open, onClose, title, message }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 overflow-y-auto h-full w-full flex justify-center items-center">
      <div className="bg-gray-800 p-4 md:p-8 rounded-lg shadow-lg">
        <div className="flex flex-col items-center">
          {/* Success Icon */}
          <svg
            className="h-12 w-12 bg-green-600 rounded-full p-2 text-white mb-4"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <h3 className="text-lg font-semibold text-green-400 mb-2">{title}</h3>
          <p className="mb-4 text-gray-300">{message}</p>
          <button
            className="px-4 py-2 bg-gray-700 rounded hover:bg-gray-600 text-white"
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export const WaitDialog = ({ open, onClose }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 overflow-y-auto h-full w-full flex justify-center items-center">
      <div className="bg-gray-800 p-4 md:p-8 rounded-lg shadow-lg">
        <div className="flex flex-col items-center">
          {/* Loading Icon */}
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-yellow-500"></div>
          <h3 className="text-lg font-semibold text-yellow-400 mb-2 mt-4">Operation in Progress</h3>
          <p className="mb-4 text-gray-300">Processing... Please wait a moment.</p>
          <button
            className="px-4 py-2 bg-gray-700 rounded hover:bg-gray-600 text-white"
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
