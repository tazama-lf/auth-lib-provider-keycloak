export const fetchApi = async (url: string, options?: RequestInit): Promise<unknown> => {
  try {
    const response = await fetch(url, { method: 'GET', ...options });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    throw new Error((error as Error).message);
  }
};

export const fetchWithAuth = async (url: string, token: string, options?: RequestInit): Promise<unknown> => {
  const authOptions: RequestInit = {
    ...options,
    headers: {
      ...options?.headers,
      Authorization: `Bearer ${token}`,
    },
  };
  return await fetchApi(url, authOptions);
};
