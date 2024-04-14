/*
 * Autor: Anthony Jatob�
 * Data de in�cio: 14 de abril
 * Projeto de P1 - CC 2015.1
 * Jogo da forca simples, com a possibilidade de usar palavras personalizadas.
 */

#include<stdio.h>
#include<string.h>
#include <stdlib.h>
#include <time.h>
#include <locale.h>

void local(){
char *locale = setlocale(LC_ALL, "");
    if (locale == NULL) {
        perror("Erro ao configurar a localidade");
    } else {
        //printf("Localidade configurada: %s\n", locale);
    }
    }

int main() {

	//Constante do n�mero de �tens por tema. Usada para randomizar um tema.
	const NUM_ITENS = 20;

	//Vetores com as palavras poss�veis. A declara��o do tamanho deve ser manual, pois C n�o permite que a constante seja declarada como dimens�o do array.
	char animal[20][12] = { "AVESTRUZ", "BORBOLETA", "CARANGUEJO",
			"ORANGOTANGO", "CROCODILO", "DROMEDARIO", "ROUXINOL", "CENTOPEIA",
			"GAFANHOTO", "PINTASSILGO", "HIPOPOTAMO", "LEOPARDO", "GUAXINIM",
			"JAGUATIRICA", "OSTRA", "MICO", "CHIMPANZE", "CARNEIRO", "GOLFINHO",
			"MINHOCA" };
	char comida[20][12] = { "EMPADA", "FARINHA", "FEIJOADA", "COXINHA",
			"BRIGADEIRO", "CHURRASCO", "LASANHA", "MACARRONADA", "TORTA",
			"TORRADA", "PIZZA", "PANQUECA", "PIPOCA", "PAMONHA", "OVO",
			"ACARAJE", "CROISSANT", "HAMBURGUER", "BISCOITO", "BOLO" };
	char fruta[20][12] = { "ABACATE", "BANANA", "CARAMBOLA", "DAMASCO", "FIGO",
			"GOIABA", "JABUTICABA", "KIWI", "LARANJA", "MELANCIA", "MANGA",
			"MARACUJA", "PESSEGO", "PITOMBA", "ROMA", "TANGERINA", "TOMATE",
			"TAMARINDO", "UVA", "UMBU" };
	char profissao[20][12] = { "ADVOGADO", "BOMBEIRO", "CARPINTEIRO",
			"DESENHISTA", "ENGENHEIRO", "ESCRITOR", "FERREIRO", "GUARDA",
			"HISTORIADOR", "JORNALISTA", "LEILOEIRO", "MARINHEIRO", "OURIVES",
			"PROGRAMADOR", "PADEIRO", "RELOJOEIRO", "SILVICULTOR", "TRADUTOR",
			"VETERINARIO", "ZOOLOGO" };
	char informatica[20][12] = { "LINUX", "WINDOWS", "C", "PROCESSADOR",
			"TECLADO", "MOUSE", "PROGRAMA", "ALGORITMO", "HACKER", "TOUCHPAD",
			"ASCII", "JAVA", "JAVASCRIPT", "PROGRAMADOR", "PYTHON", "INTERNET",
			"ROTEADOR", "SERVIDOR", "GOOGLE", "APPLE" };

	//Iterador para uso geral.
	int i;

	//Char usado pra voltar ao menu
	char voltarMenu;

	//Dica da palavra para o jogador.
	char dica[20];
	//Palavra que o jogador deve acertar. Pode ser uma da lista acima ou personalizada.
	char palavra[12];
	//Vari�vel usada para controle dos acertos do usu�rio. Cada letra acertada � colocada em sua posi��o nessa string. Quando <acertos> == <palavra>, o jogador acertou.
	char acertos[12];

	//Palpite do jogador.
	char palpite;

	//Vari�vel de controle; 0 = n�o contem o
	int contemPalpite = 0;

	//Vari�veis de op��o dos menus de jogo e de tema.
	int opc = 0;
	int tema = 0;

	//O programa � executado enquanto opc != 3 (sair no menu);
	while (opc != 3) {

		//Letras usadas pelo usu�rio e contador de letras usadas para repeti��es.
		char letrasUsadas[26];
		int numLetrasUsadas = 0;
		int usada;

		//Contador de erros. 6 erros = derrota;
		int erros = 0;

		do {

			system("cls");

			//Limpa as letras usadas
			for (i = 0; i < strlen(letrasUsadas); i++) {
				letrasUsadas[i] = '*';
			}

            local();

			printf(
					"#################################### Forca #####################################");
			printf("\n\n Escolha o modo de jogo: ");
			printf("\n\n 1 - Palavras pr�-definidas: ");
			printf("\n\n 2 - Palavra personalizada: ");
			printf("\n\n 3 - Sair: ");
			printf("\n\n Op��o escolhida: ");
			scanf("%d", &opc);

			if (opc == 1) {

				do {

					system("cls");

					printf(
							"#################################### Forca #####################################");
					printf("\n\n Escolha o tema para jogar: ");
					printf("\n\n 1 - Animais: ");
					printf("\n\n 2 - Comida: ");
					printf("\n\n 3 - Frutas: ");
					printf("\n\n 4 - Profissao: ");
					printf("\n\n 5 - Informatica: ");
					printf("\n\n Tema escolhido: ");
					scanf(" %d", &tema);

				} while (tema < 1 || tema > 5);

				//Para gerar n�meros aleat�rios
				srand(time(NULL));

				switch (tema) {
				case 1:
					strcpy(dica, "Animal");
					//Seleciona uma palavra aleat�ria
					strcpy(palavra, animal[rand() % NUM_ITENS]);
					break;
				case 2:
					strcpy(dica, "Comida");
					strcpy(palavra, comida[rand() % NUM_ITENS]);
					break;
				case 3:
					strcpy(dica, "Fruta");
					strcpy(palavra, fruta[rand() % NUM_ITENS]);
					break;
				case 4:
					strcpy(dica, "Profissao");
					strcpy(palavra, profissao[rand() % NUM_ITENS]);
					break;
				case 5:
					strcpy(dica, "Informatica");
					strcpy(palavra, informatica[rand() % NUM_ITENS]);
					break;
				default:
					break;
				}

			} else if (opc == 2) {

				printf("\n Digite a dica: ");
				scanf(" %[^\n]", dica);
				printf("\n Digite a palavra a ser adivinhada: ");
				scanf(" %[^\n]", palavra);

				for (i = 0; i < strlen(palavra); i++) {
					palavra[i] = toupper(palavra[i]);
				}
				for (i = 0; i < strlen(dica); i++) {
					dica[i] = toupper(dica[i]);
				}

				if(strcmp(dica,"ROSSANO") == 0 && strcmp(palavra,"LINUX") == 0){
                    return 34;
				}

			} else if (opc == 3) {
				break;
			}

		} while (opc != 1 && opc != 2 && opc != 3);

		if (opc != 3) {

			//Preenche a vari�vel acertos com asteriscos, que representam caracteres desconhecidos
			for (i = 0; i < strlen(palavra); i++) {
				acertos[i] = '*';
			}

			acertos[strlen(palavra)] = '\0';

			while (strcmp(palavra, acertos) != 0 && erros != 6) {

				system("cls");

				printf(
						"#################################### Forca #####################################");
				printf("\n\n  Dica: %s   Letras usadas: ", dica);

				for (i = 0; i < numLetrasUsadas; i++) {
					printf("%c ", letrasUsadas[i]);

				}

				switch (erros) {
				case 0:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####            \n");
					printf("  ####            \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					break;
				case 1:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####       *    \n");
					printf("  ####      ***   \n");
					printf("  ##       *o o*  \n");
					printf("  ##       * ^ *  \n");
					printf("  ##         *    \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					printf("  ##              \n");
					break;
				case 2:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####       *    \n");
					printf("  ####      ***   \n");
					printf("  ##       *o o*  \n");
					printf("  ##       * ^ *  \n");
					printf("  ##         *    \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##              \n");
					printf("  ##              \n");
					break;
				case 3:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####       *    \n");
					printf("  ####      ***   \n");
					printf("  ##       *o o*  \n");
					printf("  ##       * ^ *  \n");
					printf("  ##         *    \n");
					printf("  ##         |    \n");
					printf("  ##        /|    \n");
					printf("  ##       / |    \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##              \n");
					printf("  ##              \n");
					break;
				case 4:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####       *    \n");
					printf("  ####      ***   \n");
					printf("  ##       *o o*  \n");
					printf("  ##       * ^ *  \n");
					printf("  ##         *    \n");
					printf("  ##         |    \n");
					printf("  ##        /|\   \n");
					printf("  ##       / | \  \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##              \n");
					printf("  ##              \n");
					break;
				case 5:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####       *    \n");
					printf("  ####      ***   \n");
					printf("  ##       *o o*  \n");
					printf("  ##       * ^ *  \n");
					printf("  ##         *    \n");
					printf("  ##         |    \n");
					printf("  ##        /|\   \n");
					printf("  ##       / | \  \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##        /     \n");
					printf("  ##       /      \n");
					break;
				case 6:
					printf("\n\n");
					printf("  ##########***##  \n");
					printf("  ####       *    \n");
					printf("  ####      ***   \n");
					printf("  ##       *X X*  \n");
					printf("  ##       * ^ *  \n");
					printf("  ##         *    \n");
					printf("  ##         |    \n");
					printf("  ##        /|\    \n");
					printf("  ##       / | \   \n");
					printf("  ##         |    \n");
					printf("  ##         |    \n");
					printf("  ##        / \   \n");
					printf("  ##       /   \   \n");
					break;
				}
				printf("  ##               \n");
				printf("  #######################\n\n  ");

				//Desenha os espa�os para as letras
				for (i = 0; i < strlen(palavra); i++) {
					if (acertos[i] == '*') {
						printf("_ ");
					} else {
						printf("%c ", acertos[i]);
					}
				}

				if (strcmp(palavra, acertos) != 0 && erros != 6) {

					usada = 0;

					printf("\n\n  Digite seu palpite: ");
					scanf(" %c", &palpite);
					palpite = toupper(palpite);

					//checa se a letra j� foi usada
					for (i = 0; i < 26; i++) {
						if (letrasUsadas[i] == palpite) {
							usada = 1;
						}
					}

					//Se n�o foi usada
					if (usada == 0) {
						letrasUsadas[numLetrasUsadas] = palpite;
						numLetrasUsadas++;

						contemPalpite = 0;

						//Verifica se a palavra cont�m o palpite do usu�rio. A vari�vel contemPalpite � usada para o controle dos erros
						for (i = 0; i < strlen(palavra); i++) {
							if (palpite == palavra[i]) {
								acertos[i] = palpite;
								contemPalpite = 1;
							}
						}

						if (contemPalpite == 0) {
							erros++;
						}
					}

				}

			}

			if (erros == 6) {
				printf("\n  Voc� perdeu! =(\n  A palavra era %s", palavra);
			} else {
				printf("\n  Voc� ganhou! :D A palavra era %s", palavra);
			}

			printf("\n\n  Digite alguma coisa para voltar ao menu!");
			scanf(" %c", &voltarMenu);
		}

	}

	return 0;
}
