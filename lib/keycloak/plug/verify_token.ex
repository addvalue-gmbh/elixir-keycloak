defmodule Keycloak.Plug.VerifyToken do
  @moduledoc """
  Plug for verifying authorization on a per request basis, verifies that a token is set in the
  `Authorization` header.

  ### Example Usage

      config :keycloak, Keycloak.Plug.VerifyToken, hmac: "foo"

      # In your plug pipeline
      plug Keycloak.Plug.VerifyToken
  """
  import Plug.Conn

  @regex ~r/^Bearer:?\s+(.+)/i

  @doc false
  def init(opts), do: opts

  @doc """
  Fetches the `Authorization` header, and verifies the token if present. If a
  valid token is passed, the decoded `%Joken.Token{}` is added as `:token`
  to the `conn` assigns.
  """
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _) do
    token =
      conn
      |> get_req_header("authorization")
      |> fetch_token()

    case Keycloak.verify(token) do
      {:ok, claims} ->
        conn
        |> assign(:claims, claims)

      {:error, message} ->
        conn
        |> put_resp_content_type("application/vnd.api+json")
        |> send_resp(401, Jason.encode!(%{error: message}))
        |> halt()
    end
  end

  @doc """
  Fetches the token from the `Authorization` headers array, attempting
  to match the token in the format `Bearer <token>`.

  ### Example

      iex> fetch_token([])
      nil

      iex> fetch_token(["abc123"])
      nil

      iex> fetch_token(["Bearer abc123"])
      "abc123"
  """
  @spec fetch_token([String.t()] | []) :: String.t() | nil
  def fetch_token([]), do: nil

  def fetch_token([token | tail]) do
    case Regex.run(@regex, token) do
      [_, token] -> String.trim(token)
      nil -> fetch_token(tail)
    end
  end
end
