import prisma from '@/_lib/prisma';

export async function getIsAdmin() {
    const count = await prisma.users.count({
        where: { role: 'ADMIN' }
    });

    return count > 0;
}