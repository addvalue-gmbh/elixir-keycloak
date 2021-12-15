defmodule Keycloak.Plug.VerifySession do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    access_token =
      get_session(conn, :access_token)

    refresh_token =
      get_session(conn, :refresh_token)

    with {:ok, claims} <- Keycloak.verify(access_token),
         {:ok, _exp} <- token_expired?(claims)
    do
      conn
    else
      {:error, :expired} ->
        case Keycloak.refresh_token(refresh_token) do
          %OAuth2.Client{} = client ->
            conn
            |> put_session(:access_token, client.token.access_token)
            |> put_session(:refresh_token, client.token.refresh_token)
          _ ->
            clear_and_redirect(conn)
        end
      _ ->
        clear_and_redirect(conn)
    end
  end

  defp token_expired?(%{"exp" => exp}) do
    if Joken.current_time() > exp do
      {:error, :expired}
    else
      {:ok, exp}
    end
  end

  defp clear_and_redirect(conn) do
    conn
    |> put_session(:access_token, nil)
    |> put_session(:refresh_token, nil)
    |> redirect("/")
    |> halt()
  end

  defp redirect(conn, url) do
    html = Plug.HTML.html_escape(url)
    body = "<html><body>You are being <a href=\"#{html}\">redirected</a>.</body></html>"

    conn
    |> put_resp_header("location", "/")
    |> put_resp_content_type("text/html")
    |> send_resp(conn.status || 302, body)
  end

end
