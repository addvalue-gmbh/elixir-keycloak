defmodule Keycloak do
  @moduledoc """
  An OAuth2.Strategy implementation for authorizing with a
  [Keycloak](http://www.keycloak.org/) server.

  ## Example

  #### Phoenix controller

      def login(conn, _) do
        redirect(conn, external: Keycloak.authorize_url!())
      end

      def callback(conn, %{"code" => code}) do
        %{token: token} = Keycloak.get_token!(code: code)

        conn
        |> put_session(:token, token)
        |> redirect(to: "/manage")
      end
  """

  use OAuth2.Strategy

  alias Keycloak.Client
  alias OAuth2.Strategy.AuthCode

  @doc """
  Creates a authori
  """
  def authorize_url!(params \\ []) do
    Client.new()
    |> OAuth2.Client.authorize_url!(params)
  end

  @doc """
  Creates a `OAuth2.Client` using the keycloak configuration and
  attempts fetch a access token.
  """
  @spec get_token!(keyword(), keyword()) :: any()
  def get_token!(params \\ [], _headers \\ []) do
    data = Keyword.merge(params, client_secret: Client.new().client_secret)

    Client.new()
    |> OAuth2.Client.get_token!(data)
  end

  @doc """
  Returns the authorize url for the keycloak client.
  """
  @spec authorize_url(OAuth2.Client.t(), keyword()) :: any()
  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  @doc """
  Gets a token given a preconfigured `OAuth2.Client`.
  """
  @spec get_token(OAuth2.Client.t(), keyword(), keyword()) :: any()
  def get_token(client, params, headers) do
    client
    |> OAuth2.Client.put_header("Accept", "application/json")
    |> AuthCode.get_token(params, headers)
  end

  @spec get_jwk() :: any()
  def get_jwk do
    GenServer.call(:keycloak, {:jwk, :default})
  end

  @spec update_documents() :: any()
  def update_documents do
    client =
      Client.new()

    with {:ok, %{ body: discovery_document}} <- Client.discovery_document(client),
         {:ok, %{ body: certs} = request } <- Client.jwks(client),
         remaining_lifetime <- remaining_lifetime(request.headers),
         {:ok, jwk} <- from_certs(certs)
    do
      {:ok,
        %{
          discovery_document: normalize_discovery_document(discovery_document),
          jwk: jwk,
          remaining_lifetime: remaining_lifetime
        }
      }
    else
      {:error, reason} ->
        {:error, :update_documents, reason}
    end
  end

  def normalize_discovery_document(discovery_document) do
    # claims_supported may be missing as it is marked RECOMMENDED by the spec, default to an empty list
    sorted_claims_supported =
      discovery_document
      |> Map.get("claims_supported", [])
      |> Enum.sort()

    # response_types_supported's presence is REQUIRED by the spec, crash when missing
    sorted_response_types_supported =
      discovery_document
      |> Map.get("response_types_supported")
      |> Enum.map(fn response_type ->
        response_type
        |> String.split()
        |> Enum.sort()
        |> Enum.join(" ")
      end)

    Map.merge(discovery_document, %{
      "claims_supported" => sorted_claims_supported,
      "response_types_supported" => sorted_response_types_supported
    })
  end

  defp remaining_lifetime(headers) do
    with headers = Enum.into(headers, %{}),
         {:ok, max_age} <- find_max_age(headers),
         {:ok, age} <- find_age(headers) do
      max_age - age
    else
      _ -> nil
    end
  end

  defp find_max_age(headers) when is_map(headers) do
    case Regex.run(~r"(?<=max-age=)\d+", Map.get(headers, "cache-control", "")) do
      [max_age] -> {:ok, String.to_integer(max_age)}
      _ -> :error
    end
  end

  defp find_age(headers) when is_map(headers) do
    case Map.get(headers, "age") do
      nil -> :error
      age -> {:ok, String.to_integer(age)}
    end
  end

  defp from_certs(certs) do
    try do
      {:ok, JOSE.JWK.from(certs)}
    rescue
      _ ->
        {:error, "certificates bad format"}
    end
  end

  @doc """
  Verifies the validity of the JSON Web Token (JWT)
  This verification will assert the token's encryption against the provider's
  JSON Web Key (JWK)
  """
  def verify(jwt) do
    jwk = get_jwk()

    with {:ok, protected} <- peek_protected(jwt),
         {:ok, decoded_protected} <- Jason.decode(protected),
         {:ok, token_alg} <- Map.fetch(decoded_protected, "alg"),
         {true, claims, _jwk} <- do_verify(jwk, token_alg, jwt)
    do
      Jason.decode(claims)
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :verify, "token claims did not contain a JSON payload"}

      {:error, :peek_protected} ->
        {:error, :verify, "invalid token format"}

      :error ->
        {:error, :verify, "no `alg` found in token"}

      {false, _claims, _jwk} ->
        {:error, :verify, "verification failed"}

      _ ->
        {:error, :verify, "verification error"}
    end
  end

  defp peek_protected(jwt) do
    try do
      {:ok, JOSE.JWS.peek_protected(jwt)}
    rescue
      _ ->
        {:error, :peek_protected}
    end
  end

  defp do_verify(%JOSE.JWK{keys: {:jose_jwk_set, jwks}}, token_alg, jwt) do
    Enum.find_value(jwks, {false, "{}", jwt}, fn jwk ->
      jwk
      |> JOSE.JWK.from()
      |> do_verify(token_alg, jwt)
      |> case do
        {false, _claims, _jwt} -> false
        verified_claims -> verified_claims
      end
    end)
  end

  defp do_verify(%JOSE.JWK{} = jwk, token_alg, jwt),
    do: JOSE.JWS.verify_strict(jwk, [token_alg], jwt)
end
