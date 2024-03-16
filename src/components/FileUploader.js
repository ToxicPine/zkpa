import React, { useState } from 'react';
import { useDropzone } from 'react-dropzone';

const FileUploader = () => {
    const [file, setFile] = useState(null);
    const [previewUrl, setPreviewUrl] = useState(null);
    const [importUrl, setImportUrl] = useState('');
    const [hash, setHash] = useState(null);
    const [hashByteArray, setHashByteArray] = useState(null);

    const { getRootProps, getInputProps } = useDropzone({
        onDrop: (acceptedFiles) => {
            const newFile = acceptedFiles[0];
            setFile(newFile);
            setPreviewUrl(URL.createObjectURL(newFile));
            handleImageUpload(newFile);
        },
        accept: {
            'image/*': [],
        },
        maxSize: 25 * 1024 * 1024, // 25MB
    });

    const handleFileChange = (e) => {
        const newFile = e.target.files[0];
        setFile(newFile);
        setPreviewUrl(URL.createObjectURL(newFile));
        handleImageUpload(newFile);
    };

    const handleImportUrlChange = (e) => {
        setImportUrl(e.target.value);
    };

    const handleImportFromUrl = () => {
        fetchImageFromUrl(importUrl);
    };

    const fetchImageFromUrl = async (url) => {
        try {
            const response = await fetch(url);
            const blob = await response.blob();
            const newFile = new File([blob], 'imported-image.jpg', { type: 'image/jpeg' });
            setFile(newFile);
            setPreviewUrl(URL.createObjectURL(newFile));
            handleImageUpload(newFile);
        } catch (error) {
            console.error('Error importing image:', error);
        }
    };

    const handleImageUpload = async (file) => {
        try {
            const formData = new FormData();
            formData.append('image', file);
            const response = await fetch('/hash_image', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error uploading image:', errorText);
                return;
            }

            const data = await response.json();
            console.log('Response data:', data);
            setHash(data.hash_hex);
            setHashByteArray(data.hash_byte_array);
        } catch (error) {
            console.error('Error uploading image:', error);
        }
    };

    const handleVerify = () => {
        // 在这里添加验证逻辑
        console.log('Verifying image...');
    };

    const handleReset = () => {
        setFile(null);
        setPreviewUrl(null);
        setImportUrl('');
        setHash(null);
        setHashByteArray(null);
    };

    return (
        <div className="flex justify-center items-center h-screen bg-black">
            <div className="bg-black rounded-lg p-8 w-2/3 max-w-4xl">
                <h2 className="text-2xl font-bold text-white mb-6">Upload Image</h2>
                <div
                    {...getRootProps()}
                    className="border-2 border-dashed border-gray-500 rounded-md p-8 mb-6"
                >
                    <input {...getInputProps()} />
                    {file || previewUrl ? (
                        <div>
                            <img
                                src={previewUrl}
                                alt={file?.name || 'Imported Image'}
                                className="max-h-64 mb-4 rounded-md"
                            />
                            <p className="text-white">{file?.name || 'Imported Image'}</p>
                            {hash && <p className="text-white">Hash: {hash}</p>}
                            {hashByteArray && (
                                <p className="text-white">
                                    Hash Byte Array: [{hashByteArray}]
                                </p>
                            )}
                        </div>
                    ) : (
                        <p className="text-gray-400">Drag and Drop image here or Choose file</p>
                    )}
                </div>
                {!file && (
                    <label className="block mb-6">
                        <span className="sr-only">Choose file</span>
                        <input
                            type="file"
                            accept="image/*"
                            className="block w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-600 file:text-white hover:file:bg-gray-500"
                            onChange={handleFileChange}
                        />
                    </label>
                )}
                <hr className="my-6 border-gray-500" />
                <div className="mb-6">
                    <h3 className="text-xl font-bold text-white mb-2">Import from URL</h3>
                    <div className="flex">
                        <input
                            type="text"
                            placeholder="Enter image URL"
                            className="flex-grow bg-gray-600 text-white p-2 rounded-l-md focus:outline-none"
                            value={importUrl}
                            onChange={handleImportUrlChange}
                        />
                        <button
                            className="bg-gray-500 text-white font-bold py-2 px-4 rounded-r-md"
                            onClick={handleImportFromUrl}
                        >
                            Import
                        </button>
                    </div>
                </div>
                <p className="text-gray-400 mb-6">Supported formats: Images</p>
                <p className="text-gray-400 mb-6">Maximum size: 25MB</p>
                <div className="flex justify-end mt-6">
                    <button
                        className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded-md mr-4"
                        onClick={handleVerify}
                    >
                        Verify
                    </button>
                    <button
                        className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-md"
                        onClick={handleReset}
                    >
                        Reset
                    </button>
                </div>
            </div>
        </div>
    );
};

export default FileUploader;